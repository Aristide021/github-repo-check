const { Client, GatewayIntentBits, EmbedBuilder } = require('discord.js');
const { Octokit } = require('@octokit/rest');
const { createLogger, format, transports } = require('winston');
const Redis = require('ioredis');
const redis = new Redis();
const { execSync } = require('child_process');

const CACHE_EXPIRATION = 60 * 60; // 1 hour in seconds
require('dotenv').config();

// Logger setup
const logger = createLogger({
  format: format.combine(
    format.timestamp(),
    format.json()
  ),
  transports: [
    new transports.File({ filename: 'error.log', level: 'error' }),
    new transports.File({ filename: 'combined.log' })
  ]
});

const client = new Client({
  intents: [GatewayIntentBits.Guilds, GatewayIntentBits.GuildMessages, GatewayIntentBits.MessageContent]
});

const octokit = new Octokit({ 
  auth: process.env.GITHUB_TOKEN,
  throttle: {
    onRateLimit: (retryAfter, options, octokit, retryCount) => {
      logger.warn(`Rate limit hit, retrying after ${retryAfter} seconds`);
      return retryCount < 2;
    },
    onSecondaryRateLimit: (retryAfter, options, octokit) => {
      logger.warn(`Secondary rate limit hit, waiting ${retryAfter} seconds`);
      return true;
    }
  }
});

// Helper Functions

async function checkRateLimit() {
  const { data: rateLimit } = await octokit.rateLimit.get();
  if (rateLimit.remaining < 100) {
    throw new Error(`Rate limit too low: ${rateLimit.remaining} remaining`);
  }
  return rateLimit;
}

async function isRepoPrivate(owner, repo) {
  try {
    const { data } = await octokit.repos.get({ owner, repo });
    return data.private;
  } catch (error) {
    logger.error('Error checking repo privacy:', error);
    return true;
  }
}

async function getCargoToml(owner, repo) {
  try {
    const { data: cargoToml } = await octokit.repos.getContent({
      owner,
      repo,
      path: 'Cargo.toml'
    });

    return Buffer.from(cargoToml.content, 'base64').toString();
  } catch (error) {
    logger.error('Error fetching Cargo.toml:', error);
    return null;
  }
}

function parseCargoToml(content) {
  const dependencies = {};
  const lines = content.split('\n');

  for (const line of lines) {
    if (line.startsWith('[') || line.trim() === '') continue; // Skip sections and empty lines
    const [name, version] = line.split('=').map(s => s.trim());
    if (name && version) {
      dependencies[name] = version.replace(/"/g, ''); // Remove quotes from version
    }
  }

  return dependencies;
}

async function runCargoAudit(owner, repo) {
  try {
    // Clone the repository
    execSync(`git clone https://github.com/${owner}/${repo}.git temp-repo`);
    
    // Run cargo audit
    const output = execSync('cargo audit --json', { cwd: './temp-repo' }).toString();
    
    // Parse the JSON output
    const auditResults = JSON.parse(output);
    
    // Clean up
    execSync('rm -rf temp-repo');
    
    return auditResults;
  } catch (error) {
    logger.error('Error running cargo audit:', error);
    return null;
  }
}

function checkSolanaVulnerabilities(code) {
  const vulnerabilities = [];

  // Check for missing owner checks
  if (!code.includes('constraint = owner.key()')) {
    vulnerabilities.push('Missing owner check: Ensure the owner is properly validated.');
  }

  // Check for improper PDA usage
  if (code.includes('Pubkey::create_program_address') && !code.includes('Pubkey::find_program_address')) {
    vulnerabilities.push('Improper PDA usage: Use `find_program_address` instead of `create_program_address` to avoid address collisions.');
  }

  // Check for missing signer checks
  if (code.includes('AccountInfo') && !code.includes('is_signer: true')) {
    vulnerabilities.push('Missing signer check: Ensure sensitive operations require a signer.');
  }

  return vulnerabilities;
}

function analyzeRustCode(code) {
  const vulnerabilities = [];

  // Check for unsafe code blocks
  if (code.includes('unsafe {')) {
    vulnerabilities.push('Unsafe code detected: Avoid using unsafe blocks unless absolutely necessary.');
  }

  // Check for improper error handling
  if (code.includes('unwrap()') || code.includes('expect(')) {
    vulnerabilities.push('Improper error handling: Avoid using `unwrap()` or `expect()`; handle errors properly.');
  }

  return vulnerabilities;
}

async function analyzeSecurity(owner, repo) {
  const securityReport = {
    dependencyVulnerabilities: [],
    solanaVulnerabilities: [],
    rustVulnerabilities: []
  };

  // Run cargo audit
  const cargoAuditResults = await runCargoAudit(owner, repo);
  if (cargoAuditResults && cargoAuditResults.vulnerabilities) {
    securityReport.dependencyVulnerabilities = cargoAuditResults.vulnerabilities.map(vuln => vuln.advisory.title);
  }

  // Fetch and analyze Rust code
  const { data: rustCode } = await octokit.repos.getContent({
    owner,
    repo,
    path: 'src/lib.rs' // Path to the main Rust file
  });
  const codeContent = Buffer.from(rustCode.content, 'base64').toString();
  securityReport.solanaVulnerabilities = checkSolanaVulnerabilities(codeContent);
  securityReport.rustVulnerabilities = analyzeRustCode(codeContent);

  return securityReport;
}

function generateSecuritySummary(securityReport) {
  const summary = [];

  if (securityReport.dependencyVulnerabilities.length > 0) {
    summary.push(`🔒 **Dependency Vulnerabilities**:\n${securityReport.dependencyVulnerabilities.join('\n')}`);
  }
  if (securityReport.solanaVulnerabilities.length > 0) {
    summary.push(`⚠️ **Solana Vulnerabilities**:\n${securityReport.solanaVulnerabilities.join('\n')}`);
  }
  if (securityReport.rustVulnerabilities.length > 0) {
    summary.push(`🛑 **Rust Vulnerabilities**:\n${securityReport.rustVulnerabilities.join('\n')}`);
  }

  return summary.length ? summary.join('\n') : '✅ No security vulnerabilities detected.';
}

async function analyzeRepository(owner, repo) {
  const cacheKey = `repo:${owner}:${repo}`;
  const cached = await redis.get(cacheKey);
  
  if (cached) {
    logger.info('Cache hit for repository:', { owner, repo });
    return JSON.parse(cached);
  }

  try {
    await checkRateLimit();
    
    if (await isRepoPrivate(owner, repo)) {
      throw new Error('Repository is private or inaccessible');
    }

    const codeUniqueness = await checkCodeUniqueness(owner, repo);
    const securityAnalysis = await analyzeSecurity(owner, repo);
    const analysis = {
      codeUniqueness,
      securityAnalysis,
      authenticity: calculateAuthenticityScore({}, codeUniqueness) // Placeholder for repoInfo
    };

    await redis.set(cacheKey, JSON.stringify(analysis), 'EX', CACHE_EXPIRATION);
    return analysis;
  } catch (error) {
    logger.error('Repository analysis error:', { owner, repo, error: error.message });
    throw error;
  }
}

// Discord Event Handlers
client.on('ready', () => {
  logger.info('Bot is ready!');
});

client.on('messageCreate', async message => {
  if (message.author.bot) return;
  
  const args = message.content.split(' ');
  const command = args[0].toLowerCase();
  
  if (command === '!check' || command === '!detailed') {
    try {
      const repoPath = args[1];
      if (!repoPath) {
        throw new Error('Please provide a repository path (owner/repo)');
      }
      
      const [owner, repo] = repoPath.split('/');
      if (!owner || !repo) {
        throw new Error('Invalid repository format. Use owner/repo');
      }

      if (command === '!detailed') {
        const loadingMsg = await message.reply('Analyzing repository in detail, please wait...');
        try {
          const analysis = await analyzeRepository(owner, repo);
          const embed = new EmbedBuilder()
            .setTitle(`🔍 Detailed Analysis: ${owner}/${repo}`)
            .setColor('#FFD700')
            .addFields(
              { name: '🏆 Notable Features & Strengths', value: 'Placeholder for strengths' },
              { name: '⚠️ Potential Issues', value: generateSecuritySummary(analysis.securityAnalysis) },
              { name: 'Repository Score', value: `${analysis.authenticity}/100` }
            );
          
          await loadingMsg.delete();
          await message.reply({ embeds: [embed] });
        } catch (error) {
          await loadingMsg.edit(`Error: ${error.message}`);
        }
      } else {
        const analysis = await analyzeRepository(owner, repo);
        const embed = new EmbedBuilder()
          .setTitle(`Repository Analysis: ${owner}/${repo}`)
          .setColor('#00ff00')
          .addFields(
            { name: 'Authenticity Score', value: `${analysis.authenticity}/100`, inline: true },
            { name: 'Repository Status', value: analysis.authenticity >= 70 ? '✅ Legitimate and well-maintained' : '⚠️ Needs review', inline: true },
            { name: 'Code Uniqueness', value: analysis.codeUniqueness.message, inline: true }
          );
        await message.reply({ embeds: [embed] });
      }
    } catch (error) {
      logger.error('Command error:', { 
        command, 
        error: error.message,
        user: message.author.tag,
        guild: message.guild?.name 
      });
      
      const errorMessage = getErrorMessage(error);
      await message.reply(errorMessage);
    }
  }
});

function getErrorMessage(error) {
  const errorMessages = {
    'Rate limit too low': 'Bot is busy. Please try again in a few minutes.',
    'Repository is private': 'Cannot analyze private repositories.',
    'Not Found': 'Repository not found or inaccessible.',
    default: 'An error occurred while analyzing the repository.'
  };

  return errorMessages[error.message] || errorMessages.default;
}

// Start the bot
client.login(process.env.DISCORD_TOKEN).catch(error => {
  logger.error('Login error:', error);
  process.exit(1);
});