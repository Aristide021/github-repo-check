const { Client, GatewayIntentBits, EmbedBuilder } = require('discord.js');
const { Octokit } = require('@octokit/rest');
const { createLogger, format, transports } = require('winston');
const Redis = require('ioredis');
const redis = new Redis();

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

    // ... [Previous analyze code remains the same until checkCodeUniqueness] ...
  } catch (error) {
    logger.error('Repository analysis error:', { owner, repo, error: error.message });
    throw error;
  }
}

async function checkCodeUniqueness(owner, repo) {
  try {
    const codeFiles = await getAllCodeFiles(owner, repo);
    const similarities = await findCodeSimilarities(codeFiles);
    
    return {
      isUnique: similarities.score > 0.8,
      message: similarities.score > 0.8 ? 
        'No significant code similarities found' : 
        `Warning: ${Math.round((1 - similarities.score) * 100)}% similar code found`,
      details: similarities.matches
    };

    await redis.set(cacheKey, JSON.stringify(analysis), 'EX', CACHE_EXPIRATION);
    return analysis;
  } catch (error) {
    logger.error('Code uniqueness check error:', error);
    return {
      isUnique: false,
      message: 'Unable to verify code uniqueness',
      details: []
    };
  }
}

async function getAllCodeFiles(owner, repo) {
  const files = [];
  async function getFiles(path = '') {
    const { data } = await octokit.repos.getContent({
      owner,
      repo,
      path
    });

    for (const item of data) {
      if (item.type === 'file' && isCodeFile(item.name)) {
        const content = await octokit.repos.getContent({
          owner,
          repo,
          path: item.path
        });
        files.push({
          path: item.path,
          content: Buffer.from(content.data.content, 'base64').toString()
        });
      } else if (item.type === 'dir') {
        await getFiles(item.path);
      }
    }
  }
  
  await getFiles();
  return files;
}

function isCodeFile(filename) {
  const codeExtensions = ['.js', '.py', '.java', '.cpp', '.go', '.rs', '.ts'];
  return codeExtensions.some(ext => filename.endsWith(ext));
}

async function findCodeSimilarities(files) {
  const matches = [];
  let totalSimilarity = 0;

  for (let i = 0; i < files.length; i++) {
    for (let j = i + 1; j < files.length; j++) {
      const similarity = calculateSimilarity(files[i].content, files[j].content);
      if (similarity > 0.8) {
        matches.push({
          file1: files[i].path,
          file2: files[j].path,
          similarity
        });
        totalSimilarity += similarity;
      }
    }
  }

  return {
    score: matches.length ? 1 - (totalSimilarity / matches.length) : 1,
    matches
  };
}

function calculateSimilarity(str1, str2) {
  // Implement Levenshtein distance or more sophisticated code similarity algorithm
  const length = Math.max(str1.length, str2.length);
  const distance = levenshteinDistance(str1, str2);
  return 1 - (distance / length);
}

function levenshteinDistance(str1, str2) {
  const matrix = Array(str2.length + 1).fill().map(() => Array(str1.length + 1).fill(0));
  
  for (let i = 0; i <= str1.length; i++) matrix[0][i] = i;
  for (let j = 0; j <= str2.length; j++) matrix[j][0] = j;
  
  for (let j = 1; j <= str2.length; j++) {
    for (let i = 1; i <= str1.length; i++) {
      const cost = str1[i - 1] === str2[j - 1] ? 0 : 1;
      matrix[j][i] = Math.min(
        matrix[j - 1][i] + 1,
        matrix[j][i - 1] + 1,
        matrix[j - 1][i - 1] + cost
      );
    }
  }
  
  return matrix[str2.length][str1.length];
}

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
              { name: '🏆 Notable Features & Strengths', value: generateDetailedStrengths(analysis) },
              { name: '⚠️ Potential Issues', value: generateDetailedIssues(analysis) },
              { name: 'Repository Score', value: `${analysis.authenticity}/100` }
            );
          
          await loadingMsg.delete();
          await message.reply({ embeds: [embed] });
        } catch (error) {
          await loadingMsg.edit(`Error: ${error.message}`);
        }
      } else {
        const analysis = await analyzeRepository(owner, repo);
        const embed = createBasicEmbed(owner, repo, analysis);
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

function createBasicEmbed(owner, repo, analysis) {
  return new EmbedBuilder()
    .setTitle(`Repository Analysis: ${owner}/${repo}`)
    .setColor('#00ff00')
    .addFields(
      { name: 'Authenticity Score', value: `${analysis.authenticity}/100`, inline: true },
      { name: 'Repository Status', value: analysis.authenticity >= 70 ? '✅ Legitimate and well-maintained' : '⚠️ Needs review', inline: true },
      { name: 'Code Uniqueness', value: analysis.codeUniqueness.message, inline: true },
      { name: 'Fork Analysis', value: formatForkAnalysis(analysis.forks) },
      { name: 'Community Engagement', value: formatCommunityMetrics(analysis.community) }
    );
}

function formatForkAnalysis(forks) {
  return [
    `Total Forks: ${forks.total}`,
    `Active Forks: ${forks.active}`,
    'Notable Forks:',
    ...forks.notable.slice(0, 5)
  ].join('\n');
}

function formatCommunityMetrics(community) {
  return [
    `Issues: ${community.issues.open}/${community.issues.total} open`,
    `PRs: ${community.prs.open}/${community.prs.total} open`,
    `Issue Resolution Rate: ${community.issues.resolutionRate}%`,
    `PR Merge Rate: ${community.prs.mergeRate}%`,
    `Avg Response Time: ${community.responseTime}h`
  ].join('\n');
}

function getErrorMessage(error) {
  const errorMessages = {
    'Rate limit too low': 'Bot is busy. Please try again in a few minutes.',
    'Repository is private': 'Cannot analyze private repositories.',
    'Not Found': 'Repository not found or inaccessible.',
    default: 'An error occurred while analyzing the repository.'
  };

  return errorMessages[error.message] || errorMessages.default;
}

process.on('unhandledRejection', (error) => {
  logger.error('Unhandled rejection:', error);
});

client.on('error', (error) => {
  logger.error('Discord client error:', error);
});

client.login(process.env.DISCORD_TOKEN).catch(error => {
  logger.error('Login error:', error);
  process.exit(1);
});

    return score;
  } catch (error) {
    logger.error('Documentation score error:', error);
    return 0;
  }
}

async function calculateReleaseFrequency(owner, repo) {
  try {
    const { data: releases } = await octokit.repos.listReleases({ owner, repo });
    if (releases.length < 2) return 0;
    
    const newest = new Date(releases[0].created_at);
    const oldest = new Date(releases[releases.length - 1].created_at);
    const monthsDiff = (newest - oldest) / (30 * 24 * 60 * 60 * 1000);
    
    return releases.length / monthsDiff;
  } catch (error) {
    logger.error('Release frequency error:', error);
    return 0;
  }
}

async function estimateTestCoverage(owner, repo) {
  try {
    const files = await getAllCodeFiles(owner, repo);
    const testFiles = files.filter(f => 
      f.path.includes('test') || 
      f.path.includes('spec') ||
      f.path.endsWith('.test.js') ||
      f.path.endsWith('.spec.js')
    );
    
    if (testFiles.length === 0) return 0;
    
    const codeLines = files
      .filter(f => !f.path.includes('test') && !f.path.includes('spec'))
      .reduce((sum, file) => sum + file.content.split('\n').length, 0);
    
    const testLines = testFiles
      .reduce((sum, file) => sum + file.content.split('\n').length, 0);
    
    return Math.min(100, Math.round((testLines / codeLines) * 100));
  } catch (error) {
    logger.error('Test coverage error:', error);
    return 0;
  }
}

function calculateAverageResponseTime(issues) {
  const responseTimes = issues
    .filter(issue => issue.comments > 0)
    .map(issue => {
      const created = new Date(issue.created_at);
      const firstResponse = new Date(issue.updated_at);
      return (firstResponse - created) / (60 * 60 * 1000); // hours
    });
  
  return responseTimes.length ? 
    responseTimes.reduce((sum, time) => sum + time, 0) / responseTimes.length : 
    0;
}

function calculateAuthenticityScore(repoInfo, codeUniqueness) {
  let score = 0;
  
  // Code uniqueness (40 points)
  score += codeUniqueness.score * 40;
  
  // Repository age (15 points)
  const ageInMonths = (Date.now() - new Date(repoInfo.created_at)) / (30 * 24 * 60 * 60 * 1000);
  score += Math.min(15, ageInMonths);
  
  // Stars and forks (15 points)
  const popularity = Math.log10(repoInfo.stargazers_count + repoInfo.forks_count + 1);
  score += Math.min(15, popularity * 3);
  
  // Activity (15 points)
  const lastUpdateDays = (Date.now() - new Date(repoInfo.updated_at)) / (24 * 60 * 60 * 1000);
  score += Math.max(0, 15 - lastUpdateDays / 2);
  
  // Repository completeness (15 points)
  score += repoInfo.has_issues ? 3 : 0;
  score += repoInfo.has_wiki ? 3 : 0;
  score += repoInfo.has_projects ? 3 : 0;
  score += repoInfo.description ? 3 : 0;
  score += repoInfo.homepage ? 3 : 0;
  
  return Math.round(score);
}

// Discord event handlers
client.on('ready', () => {
  logger.info('Bot is ready!');
});

client.on('messageCreate', async message => {
  if (message.author.bot) return;
  
  if (message.content === '!verify') {
    const verificationId = crypto.randomBytes(32).toString('hex');
    const verifyUrl = `${process.env.OAUTH_BASE_URL}/auth/reddit?state=${verificationId}`;
    
    pendingVerifications.set(verificationId, {
      discordId: message.author.id,
      expires: Date.now() + 600000 // 10 minute expiry
    });

    try {
      await message.author.send({
        embeds: [new EmbedBuilder()
          .setColor('#FF4500')
          .setTitle('🔒 Reddit Verification')
          .setDescription(`Click here to verify your Reddit account: ${verifyUrl}\nLink expires in 10 minutes.`)
          .setFooter({ text: 'Requires r/memecoins subscription' })]
      });
      if (message.guild) {
        await message.reply('Check your DMs for verification instructions! 📬');
      }
    } catch (error) {
      await message.reply('Unable to send DM. Please enable DMs from server members and try again.');
    }
    return;
  }

  if (message.content.startsWith('!check') || message.content.startsWith('!detailed')) {
    const args = message.content.split(' ');
    if (args.length !== 2) {
      await message.reply('Please provide a GitHub repository URL.');
      return;
    }

    const repoPath = args[1];
    try {
      let [owner, repo] = repoPath.split('/');
      if (!owner || !repo) {
        throw new Error('Invalid repository format. Use owner/repo');
      }

      // Clean up repo name if full URL was provided
      repo = repo.replace(/\.git$/, '');
      if (owner.includes('github.com')) {
        [, owner] = owner.split('github.com/');
      }

      if (message.content.startsWith('!detailed')) {
        const loadingMsg = await message.reply('Analyzing repository in detail, please wait...');
        try {
          const analysis = await analyzeRepository(owner, repo, message.author.id);
          const embed = new EmbedBuilder()
            .setTitle(`🔍 Detailed Analysis: ${owner}/${repo}`)
            .setColor('#FFD700')
            .addFields(
              { name: '🏆 Notable Features & Strengths', value: generateDetailedStrengths(analysis) },
              { name: '⚠️ Potential Issues', value: generateDetailedIssues(analysis) },
              { name: 'Repository Score', value: `${analysis.authenticity}/100` }
            );
          
          await loadingMsg.delete();
          await message.reply({ embeds: [embed] });
        } catch (error) {
          if (error.message.includes('Access denied')) {
            await loadingMsg.edit('⚠️ You need to verify your access first. Use !verify to get started.');
          } else {
            await loadingMsg.edit(`Error: ${error.message}`);
          }
        }
      } else {
        const analysis = await analyzeRepository(owner, repo, message.author.id);
        const embed = createBasicEmbed(owner, repo, analysis);
        await message.reply({ embeds: [embed] });
      }
    } catch (error) {
      logger.error('Command error:', { 
        command: args[0], 
        error: error.message,
        user: message.author.tag,
        guild: message.guild?.name 
      });
      
      let errorMessage = getErrorMessage(error);
      if (error.message.includes('Access denied')) {
        errorMessage = '⚠️ You need to verify your access first. Use !verify to get started.';
      }
      await message.reply(errorMessage);
    }
  }
});

// OAuth routes
passport.use(new RedditStrategy({
    clientID: process.env.REDDIT_CLIENT_ID,
    clientSecret: process.env.REDDIT_CLIENT_SECRET,
    callbackURL: process.env.OAUTH_CALLBACK_URL
  },
  async function(accessToken, refreshToken, profile, done) {
    try {
      const user = await reddit.getUser(profile.name);
      const subscriptions = await user.getSubscriptions();
      const isSubbed = subscriptions.some(sub => 
        sub.display_name.toLowerCase() === 'memecoins'
      );

      if (!isSubbed) {
        return done(null, false, { message: 'Not subscribed to r/memecoins' });
      }

      const verificationId = profile.state;
      const verification = pendingVerifications.get(verificationId);
      if (!verification || verification.expires < Date.now()) {
        return done(null, false, { message: 'Invalid or expired verification link' });
      }

      await redis.set(`verified:${verification.discordId}`, JSON.stringify({
        redditUsername: profile.name,
        verifiedAt: Date.now(),
        accessToken
      }));

      pendingVerifications.delete(verificationId);
      return done(null, profile);
    } catch (error) {
      return done(error);
    }
  }
));

app.get('/auth/reddit', 
  (req, res, next) => {
    if (!pendingVerifications.has(req.query.state)) {
      return res.status(400).send('Invalid verification link');
    }
    next();
  },
  passport.authenticate('reddit', { scope: ['identity', 'mysubreddits'] })
);

app.get('/auth/reddit/callback',
  passport.authenticate('reddit', { failureRedirect: '/error' }),
  async function(req, res) {
    try {
      const discordId = pendingVerifications.get(req.query.state).discordId;
      const guild = await client.guilds.fetch(process.env.GUILD_ID);
      const member = await guild.members.fetch(discordId);
      await member.roles.add(process.env.BETA_TESTER_ROLE_ID);
      res.send('✅ Verification successful! Return to Discord.');
    } catch (error) {
      logger.error('Verification error:', error);
      res.status(500).send('Verification failed');
    }
  }
);

// Error handling
process.on('unhandledRejection', (error) => {
  logger.error('Unhandled rejection:', error);
});

client.on('error', (error) => {
  logger.error('Discord client error:', error);
});

// Start the servers
const port = process.env.PORT || 3000;
app.listen(port, () => {
  logger.info(`OAuth server listening on port ${port}`);
});

client.login(process.env.DISCORD_TOKEN).catch(error => {
  logger.error('Login error:', error);
  process.exit(1);
});
