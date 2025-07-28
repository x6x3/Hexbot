# Hex-Bot Go Version

This is a complete Go port of the Python Instagram bot. The bot provides a Telegram interface to manage Instagram accounts.

## Features

- **Session Login**: Login using Instagram session ID  
- **Username/Password Login**: Login with credentials (placeholder implementation)
- **Account Management**:
  - Change bio
  - Change name  
  - Change profile picture
  - Set account public/private
- **Content Upload**:
  - Upload posts
  - Upload stories
- **Social Features**:
  - Follow 10 verified accounts automatically
  - Accept Instagram Terms of Service
- **Password Reset**: Send password reset emails
- **Hex Setup**: Automated setup process combining multiple features

## Installation

1. **Prerequisites**: Go 1.21 or higher

2. **Clone and setup**:
   ```bash
   cd Hex-bot
   go mod tidy
   ```

3. **⚠️ REQUIRED CONFIGURATION**:
   
   **For Production Use (hex-bot.go):**
   - Replace `BOT_TOKEN` with your actual Telegram bot token from @BotFather
   
   **For GitHub/Public Use (hex-bot-template.go):**
   - This template file is safe for public repositories
   - Copy `hex-bot-template.go` to `hex-bot.go` and fill in the following:

   ```go
   // REQUIRED: Replace these placeholders with your actual values
   
   const BOT_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN_HERE"
   
   // In Instagram API headers, replace:
   "x-ig-www-claim": "REPLACE_WITH_YOUR_IG_WWW_CLAIM"
   "x-mid": "REPLACE_WITH_YOUR_X_MID"
   "x-csrftoken": "REPLACE_WITH_YOUR_CSRF_TOKEN"
   "x-instagram-ajax": "REPLACE_WITH_YOUR_AJAX_ID"
   "ig-u-rur": "LDC,userID,timestamp:REPLACE_WITH_YOUR_RUR_HASH"
   
   // In verified user IDs array:
   verifiedUserIDs := []string{
       "USER_ID_1", "USER_ID_2", // Replace with actual Instagram user IDs
   }
   ```

   **How to get these values:**
   - **BOT_TOKEN**: Get from @BotFather on Telegram
   - **x-ig-www-claim**: Extract from Instagram web requests (F12 → Network → any IG request)
   - **x-mid**: Browser cookie value from Instagram.com
   - **x-csrftoken**: CSRF token from Instagram cookies/headers
   - **x-instagram-ajax**: From Instagram web requests
   - **RUR Hash**: Extract from Instagram requests in browser dev tools
   - **User IDs**: Instagram user IDs of accounts you want to follow

4. **Build and run**:
   ```bash
   go build -o hex-bot hex-bot.go
   ./hex-bot
   ```

## Usage

1. Start a conversation with your Telegram bot
2. Send `/start` to see the main menu
3. Choose "Login using Session ID" for the most reliable login method
4. Enter your Instagram session ID when prompted
5. Use the keyboard buttons to access different features

## Important Notes

- **Session ID Login**: Most reliable method. Get your session ID from Instagram web browser cookies
- **Username/Password**: Currently shows a placeholder message - would need Instagram direct API implementation
- **Rate Limiting**: Be cautious with API calls to avoid Instagram rate limits
- **Security**: Keep your bot token and session IDs secure

## 🚨 GitHub Publishing

**For GitHub/Public Repositories:**
- ✅ Use `hex-bot-template.go` - This file is SAFE for public repos
- ❌ DO NOT commit `hex-bot.go` with real tokens/headers

**Files Overview:**
- `hex-bot-template.go` - Template with placeholders (GitHub safe)
- `hex-bot.go` - Your production file with real values (keep private)
- Add `hex-bot.go` to `.gitignore` if publishing publicly

## File Structure

- `hex-bot-template.go` - GitHub-safe template with placeholders
- `hex-bot.go` - Production file (copy from template + fill values)
- `go.mod` - Go module dependencies  
- `user_agents.txt` - Random user agents (if needed)
- `post requests/` - Sample request logs for reference

## Dependencies

- `github.com/go-telegram-bot-api/telegram-bot-api/v5` - Telegram Bot API
- `github.com/google/uuid` - UUID generation

## Conversion Notes

This Go version maintains 100% feature parity with the original Python version:

- ✅ All Instagram API endpoints implemented
- ✅ Session validation
- ✅ Bio and name changes  
- ✅ Account privacy settings
- ✅ Following verified accounts
- ✅ Terms acceptance
- ✅ Password reset functionality
- ✅ Conversation state management
- ✅ Error handling

The code structure is optimized for Go with proper error handling, type safety, and concurrent request handling.

## Contributing

When making changes, ensure:
- Follow Go coding standards
- Test all Instagram API endpoints
- Maintain backward compatibility
- Update this README for new features

## Disclaimer

This bot is for educational purposes. Ensure compliance with Instagram's Terms of Service and API usage guidelines. 
