package main

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/google/uuid"
)

// REPLACE WITH YOUR ACTUAL TELEGRAM BOT TOKEN FROM @BotFather
const BOT_TOKEN = "YOUR_TELEGRAM_BOT_TOKEN_HERE"

type UserData struct {
	Session        string `json:"session"`
	Username       string `json:"username"`
	UserID         string `json:"user_id"`
	DeviceID       string `json:"device_id"`
	FamilyDeviceID string `json:"family_device_id"`
	AndroidID      string `json:"android_id"`
	UUID           string `json:"uuid"`
	CSRFToken      string `json:"csrftoken"`
	PostImage      []byte `json:"-"`
	PostDimensions []int  `json:"-"`
}

var userData = make(map[int64]*UserData)

// Global state tracking for conversation flow
var userStates = make(map[int64]string)

func main() {
	bot, err := tgbotapi.NewBotAPI(BOT_TOKEN)
	if err != nil {
		log.Panic(err)
	}

	bot.Debug = false
	log.Printf("Authorized on account %s", bot.Self.UserName)

	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates := bot.GetUpdatesChan(u)

	for update := range updates {
		if update.Message != nil {
			handleMessage(bot, update.Message)
		}
	}
}

func getMainKeyboard() tgbotapi.ReplyKeyboardMarkup {
	return tgbotapi.NewReplyKeyboard(
		tgbotapi.NewKeyboardButtonRow(
			tgbotapi.NewKeyboardButton("Login using Session ID"),
		),
		tgbotapi.NewKeyboardButtonRow(
			tgbotapi.NewKeyboardButton("Login username:pass"),
		),
		tgbotapi.NewKeyboardButtonRow(
			tgbotapi.NewKeyboardButton("Send Password Reset"),
		),
	)
}

func getLoggedInKeyboard() tgbotapi.ReplyKeyboardMarkup {
	return tgbotapi.NewReplyKeyboard(
		tgbotapi.NewKeyboardButtonRow(
			tgbotapi.NewKeyboardButton("Change Bio"),
			tgbotapi.NewKeyboardButton("Change Name"),
			tgbotapi.NewKeyboardButton("Change Profile Picture"),
		),
		tgbotapi.NewKeyboardButtonRow(
			tgbotapi.NewKeyboardButton("Upload Post"),
			tgbotapi.NewKeyboardButton("Upload Story"),
		),
		tgbotapi.NewKeyboardButtonRow(
			tgbotapi.NewKeyboardButton("Set Public"),
			tgbotapi.NewKeyboardButton("Set Private"),
		),
		tgbotapi.NewKeyboardButtonRow(
			tgbotapi.NewKeyboardButton("Follow 10 Verified"),
			tgbotapi.NewKeyboardButton("Send Password Reset"),
		),
		tgbotapi.NewKeyboardButtonRow(
			tgbotapi.NewKeyboardButton("Hex Setup"),
			tgbotapi.NewKeyboardButton("Accept Terms"),
		),
	)
}

func handleMessage(bot *tgbotapi.BotAPI, message *tgbotapi.Message) {
	chatID := message.Chat.ID

	// Check if user is in a conversation flow
	if state, exists := userStates[chatID]; exists {
		switch state {
		case "waiting_session":
			handleSessionInput(bot, chatID, message.Text)
			return
		case "waiting_username":
			handleUsernameInput(bot, chatID, message.Text)
			return
		case "waiting_password":
			handlePasswordInput(bot, chatID, message.Text)
			return
		case "waiting_bio":
			handleBioInput(bot, chatID, message.Text)
			return
		case "waiting_name":
			handleNameInput(bot, chatID, message.Text)
			return
		case "waiting_password_reset":
			handlePasswordResetInput(bot, chatID, message.Text)
			return
		}
	}

	switch {
	case message.IsCommand() && message.Command() == "start":
		handleStart(bot, message)
	case message.Text == "Login using Session ID":
		handleLoginSessionButton(bot, message)
	case message.Text == "Login username:pass":
		handleUsernamePassLogin(bot, message)
	case message.Text == "Change Bio":
		handleBioButton(bot, message)
	case message.Text == "Change Name":
		handleNameButton(bot, message)
	case message.Text == "Change Profile Picture":
		handlePfpButton(bot, message)
	case message.Text == "Upload Post":
		handlePostButton(bot, message)
	case message.Text == "Upload Story":
		handleStoryButton(bot, message)
	case message.Text == "Set Public":
		handlePublicButton(bot, message)
	case message.Text == "Set Private":
		handlePrivateButton(bot, message)
	case message.Text == "Follow 10 Verified":
		handleFollowVerifiedButton(bot, message)
	case message.Text == "Send Password Reset":
		handlePasswordResetButton(bot, message)
	case message.Text == "Accept Terms":
		handleAcceptTermsButton(bot, message)
	case message.Text == "Hex Setup":
		handleHexSetupButton(bot, message)
	case message.Photo != nil:
		handlePhoto(bot, message)
	}
}

func handleStart(bot *tgbotapi.BotAPI, message *tgbotapi.Message) {
	msg := tgbotapi.NewMessage(message.Chat.ID, "Welcome! Please login using your session ID or username:pass.")
	msg.ReplyMarkup = getMainKeyboard()
	bot.Send(msg)
}

func generateCSRFToken() string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, 32)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

func generateDeviceID(id string) string {
	volatileID := "12345"
	hash := md5.Sum([]byte(id + volatileID))
	return "android-" + hex.EncodeToString(hash[:])[:16]
}

func generateUserAgent() string {
	devices := []string{"HUAWEI", "Xiaomi", "samsung", "OnePlus"}
	dpis := []string{"480", "320", "640", "515", "120", "160", "240", "800"}

	randResolution := (rand.Intn(7) + 2) * 180
	lowerResolution := randResolution - 180
	manufacturer := devices[rand.Intn(len(devices))]
	model := fmt.Sprintf("%s-%c%d%c%d", manufacturer,
		'a'+rand.Intn(26), rand.Intn(10), 'a'+rand.Intn(26), rand.Intn(10))
	androidVersion := rand.Intn(8) + 18
	androidRelease := fmt.Sprintf("%d.%d", rand.Intn(7)+1, rand.Intn(8))
	cpu := fmt.Sprintf("%c%c%d", 'a'+rand.Intn(26), 'a'+rand.Intn(26), rand.Intn(9000)+1000)
	resolution := fmt.Sprintf("%dx%d", randResolution, lowerResolution)
	randomL := fmt.Sprintf("%c%d%c%d%c%d", 'a'+rand.Intn(26), rand.Intn(10),
		'a'+rand.Intn(26), rand.Intn(10), 'a'+rand.Intn(26), rand.Intn(10))
	dpi := dpis[rand.Intn(len(dpis))]

	return fmt.Sprintf("Instagram 155.0.0.37.107 Android (%d/%s; %sdpi; %s; %s; %s; %s; %s; en_US)",
		androidVersion, androidRelease, dpi, resolution, manufacturer, model, cpu, randomL)
}

func checkSessionValid(sessionText string) (bool, string, string) {
	// GraphQL request
	headers := map[string]string{
		"host":                     "i.instagram.com",
		"user-agent":               "REPLACE_WITH_YOUR_INSTAGRAM_USER_AGENT",
		"x-tigon-is-retry":         "False",
		"x-fb-rmd":                 "state=URL_ELIGIBLE",
		"x-graphql-client-library": "pando",
		"x-ig-app-id":              "567067343352427",
		"content-type":             "application/x-www-form-urlencoded",
		"x-ig-capabilities":        "3brTv10=",
		"authorization":            fmt.Sprintf("Bearer IGT:2:%s", sessionText),
		"cookie":                   fmt.Sprintf("sessionid=%s", sessionText),
		"accept-encoding":          "zstd, gzip, deflate",
		"x-fb-http-engine":         "Liger",
		"x-fb-client-ip":           "True",
		"x-fb-server-cluster":      "True",
		"connection":               "keep-alive",
	}

	reqTags, _ := json.Marshal(map[string]interface{}{
		"network_tags": map[string]interface{}{
			"product":          "567067343352427",
			"purpose":          "none",
			"request_category": "graphql",
			"retry_attempt":    "0",
		},
		"application_tags": "pando",
	})
	headers["x-fb-request-analytics-tags"] = string(reqTags)

	variables, _ := json.Marshal(map[string]interface{}{"is_pando": true})
	payload := url.Values{
		"method":                              {"post"},
		"pretty":                              {"false"},
		"format":                              {"json"},
		"server_timestamps":                   {"true"},
		"locale":                              {"en_GB"},
		"fb_api_req_friendly_name":            {"HasAvatarQuery"},
		"client_doc_id":                       {"176575339118291536801493724773"},
		"enable_canonical_naming":             {"true"},
		"enable_canonical_variable_overrides": {"true"},
		"enable_canonical_naming_ambiguous_type_prefixing": {"true"},
		"variables": {string(variables)},
	}

	client := &http.Client{}
	req, _ := http.NewRequest("POST", "https://i.instagram.com/graphql_www", strings.NewReader(payload.Encode()))
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false, "", ""
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	bodyStr := string(body)

	if resp.StatusCode == 200 {
		userIDRegex := regexp.MustCompile(`"user_id":"(\d+)"`)
		usernameRegex := regexp.MustCompile(`"username":"([^"\\]+)"`)

		userIDMatch := userIDRegex.FindStringSubmatch(bodyStr)
		usernameMatch := usernameRegex.FindStringSubmatch(bodyStr)

		if len(userIDMatch) > 1 {
			userID := userIDMatch[1]
			username := ""
			if len(usernameMatch) > 1 {
				username = usernameMatch[1]
			}
			return true, username, userID
		}
		if len(usernameMatch) > 1 {
			return true, usernameMatch[1], ""
		}
	}

	// Fallback to web request
	webHeaders := map[string]string{
		"User-Agent":     "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"X-IG-App-ID":    "567067343352427",
		"X-IG-WWW-Claim": "0",
		"Cookie":         fmt.Sprintf("sessionid=%s", sessionText),
	}

	webReq, _ := http.NewRequest("GET", "https://www.instagram.com/accounts/edit/", nil)
	for k, v := range webHeaders {
		webReq.Header.Set(k, v)
	}

	webResp, err := client.Do(webReq)
	if err != nil {
		return false, "", ""
	}
	defer webResp.Body.Close()

	webBody, _ := io.ReadAll(webResp.Body)
	webBodyStr := string(webBody)

	if webResp.StatusCode == 200 {
		userIDRegex := regexp.MustCompile(`"user_id":"(\d+)"`)
		usernameRegex := regexp.MustCompile(`"username":"([^"\\]+)"`)
		userIDMatch := userIDRegex.FindStringSubmatch(webBodyStr)
		usernameMatch := usernameRegex.FindStringSubmatch(webBodyStr)

		if len(userIDMatch) > 1 {
			userID := userIDMatch[1]
			username := ""
			if len(usernameMatch) > 1 {
				username = usernameMatch[1]
			}
			return true, username, userID
		}
		if len(usernameMatch) > 1 {
			return true, usernameMatch[1], ""
		}
	}

	return false, "", ""
}

func handleLoginSessionButton(bot *tgbotapi.BotAPI, message *tgbotapi.Message) {
	chatID := message.Chat.ID
	userStates[chatID] = "waiting_session"
	msg := tgbotapi.NewMessage(chatID, "Please send your Instagram session ID:")
	bot.Send(msg)
}

func handleUsernamePassLogin(bot *tgbotapi.BotAPI, message *tgbotapi.Message) {
	chatID := message.Chat.ID
	userStates[chatID] = "waiting_username"
	msg := tgbotapi.NewMessage(chatID, "Please send your username:")
	bot.Send(msg)
}

func handleBioButton(bot *tgbotapi.BotAPI, message *tgbotapi.Message) {
	chatID := message.Chat.ID
	if userData[chatID] == nil {
		msg := tgbotapi.NewMessage(chatID, "You must login first.")
		bot.Send(msg)
		return
	}
	userStates[chatID] = "waiting_bio"
	msg := tgbotapi.NewMessage(chatID, "Send your new bio text:")
	bot.Send(msg)
}

func handleNameButton(bot *tgbotapi.BotAPI, message *tgbotapi.Message) {
	chatID := message.Chat.ID
	if userData[chatID] == nil {
		msg := tgbotapi.NewMessage(chatID, "You must login first.")
		bot.Send(msg)
		return
	}
	userStates[chatID] = "waiting_name"
	msg := tgbotapi.NewMessage(chatID, "Send your new name:")
	bot.Send(msg)
}

func handlePfpButton(bot *tgbotapi.BotAPI, message *tgbotapi.Message) {
	chatID := message.Chat.ID
	if userData[chatID] == nil {
		msg := tgbotapi.NewMessage(chatID, "You must login first.")
		bot.Send(msg)
		return
	}
	msg := tgbotapi.NewMessage(chatID, "Send the image you want to use as your profile picture:")
	bot.Send(msg)
}

func handlePostButton(bot *tgbotapi.BotAPI, message *tgbotapi.Message) {
	chatID := message.Chat.ID
	if userData[chatID] == nil {
		msg := tgbotapi.NewMessage(chatID, "You must login first.")
		bot.Send(msg)
		return
	}
	msg := tgbotapi.NewMessage(chatID, "Send the image you want to post:")
	bot.Send(msg)
}

func handleStoryButton(bot *tgbotapi.BotAPI, message *tgbotapi.Message) {
	chatID := message.Chat.ID
	if userData[chatID] == nil {
		msg := tgbotapi.NewMessage(chatID, "You must login first.")
		bot.Send(msg)
		return
	}
	msg := tgbotapi.NewMessage(chatID, "Send the image you want to upload as a story:")
	bot.Send(msg)
}

func handlePublicButton(bot *tgbotapi.BotAPI, message *tgbotapi.Message) {
	chatID := message.Chat.ID
	if userData[chatID] == nil {
		msg := tgbotapi.NewMessage(chatID, "You must login first.")
		bot.Send(msg)
		return
	}

	success := setAccountPublic(chatID)
	var responseText string
	if success {
		responseText = "Account set to public successfully!"
	} else {
		responseText = "Failed to set account to public."
	}

	msg := tgbotapi.NewMessage(chatID, responseText)
	bot.Send(msg)
}

func handlePrivateButton(bot *tgbotapi.BotAPI, message *tgbotapi.Message) {
	chatID := message.Chat.ID
	if userData[chatID] == nil {
		msg := tgbotapi.NewMessage(chatID, "You must login first.")
		bot.Send(msg)
		return
	}

	success := setAccountPrivate(chatID)
	var responseText string
	if success {
		responseText = "Account set to private successfully!"
	} else {
		responseText = "Failed to set account to private."
	}

	msg := tgbotapi.NewMessage(chatID, responseText)
	bot.Send(msg)
}

func handleFollowVerifiedButton(bot *tgbotapi.BotAPI, message *tgbotapi.Message) {
	chatID := message.Chat.ID
	if userData[chatID] == nil {
		msg := tgbotapi.NewMessage(chatID, "You must login first.")
		bot.Send(msg)
		return
	}

	progressMsg := tgbotapi.NewMessage(chatID, "Following verified accounts... 0/10")
	sentMsg, _ := bot.Send(progressMsg)

	// REPLACE WITH ACTUAL VERIFIED USER IDs YOU WANT TO FOLLOW
	verifiedUserIDs := []string{
		"USER_ID_1", "USER_ID_2", "USER_ID_3", "USER_ID_4", "USER_ID_5",
		"USER_ID_6", "USER_ID_7", "USER_ID_8", "USER_ID_9", "USER_ID_10",
	}

	successCount := 0
	failedCount := 0

	for i, userID := range verifiedUserIDs {
		if followUser(chatID, userID) {
			successCount++
		} else {
			failedCount++
		}

		editMsg := tgbotapi.NewEditMessageText(chatID, sentMsg.MessageID,
			fmt.Sprintf("Following verified accounts... %d/10", i+1))
		bot.Send(editMsg)

		time.Sleep(2 * time.Second)
	}

	finalMsg := tgbotapi.NewEditMessageText(chatID, sentMsg.MessageID,
		fmt.Sprintf("Completed! %d followed, %d failed", successCount, failedCount))
	bot.Send(finalMsg)
}

func handlePasswordResetButton(bot *tgbotapi.BotAPI, message *tgbotapi.Message) {
	chatID := message.Chat.ID
	userStates[chatID] = "waiting_password_reset"
	msg := tgbotapi.NewMessage(chatID, "Enter the username or email to send password reset:")
	bot.Send(msg)
}

func handleAcceptTermsButton(bot *tgbotapi.BotAPI, message *tgbotapi.Message) {
	chatID := message.Chat.ID
	if userData[chatID] == nil {
		msg := tgbotapi.NewMessage(chatID, "You must login first.")
		bot.Send(msg)
		return
	}

	msg := tgbotapi.NewMessage(chatID, "Accepting Instagram Terms of Service...")
	bot.Send(msg)

	success := acceptInstagramTerms(chatID)
	var responseText string
	if success {
		responseText = "Instagram Terms accepted successfully!"
	} else {
		responseText = "Failed to accept terms or bad session."
	}

	finalMsg := tgbotapi.NewMessage(chatID, responseText)
	bot.Send(finalMsg)
}

func handleHexSetupButton(bot *tgbotapi.BotAPI, message *tgbotapi.Message) {
	chatID := message.Chat.ID
	if userData[chatID] == nil {
		msg := tgbotapi.NewMessage(chatID, "You must login first.")
		bot.Send(msg)
		return
	}

	msg := tgbotapi.NewMessage(chatID, "Starting Hex Setup...\n\nPlease send 1 photo that will be used for 1 story and 2 posts:")
	bot.Send(msg)
}

func handlePhoto(bot *tgbotapi.BotAPI, message *tgbotapi.Message) {
	chatID := message.Chat.ID
	if userData[chatID] == nil {
		msg := tgbotapi.NewMessage(chatID, "You must login first.")
		bot.Send(msg)
		return
	}

	// Download the photo
	photoSize := message.Photo[len(message.Photo)-1]
	fileConfig := tgbotapi.FileConfig{FileID: photoSize.FileID}
	file, err := bot.GetFile(fileConfig)
	if err != nil {
		msg := tgbotapi.NewMessage(chatID, "Failed to download image.")
		bot.Send(msg)
		return
	}

	fileURL := fmt.Sprintf("https://api.telegram.org/file/bot%s/%s", BOT_TOKEN, file.FilePath)
	resp, err := http.Get(fileURL)
	if err != nil {
		msg := tgbotapi.NewMessage(chatID, "Failed to download image.")
		bot.Send(msg)
		return
	}
	defer resp.Body.Close()

	imageData, err := io.ReadAll(resp.Body)
	if err != nil {
		msg := tgbotapi.NewMessage(chatID, "Failed to process image.")
		bot.Send(msg)
		return
	}

	// Store image data for later use
	if userData[chatID] == nil {
		userData[chatID] = &UserData{}
	}
	userData[chatID].PostImage = imageData

	msg := tgbotapi.NewMessage(chatID, "Image received! Processing...")
	bot.Send(msg)
}

func setAccountPublic(chatID int64) bool {
	data := userData[chatID]
	if data == nil {
		return false
	}

	uuidVal := data.UUID
	if uuidVal == "" {
		uuidVal = uuid.New().String()
	}

	deviceID := data.AndroidID
	if deviceID == "" {
		deviceID = generateDeviceID(fmt.Sprintf("%f", rand.Float64()))
	}

	userID := data.UserID
	sessionID := data.Session
	csrftoken := data.CSRFToken

	headers := map[string]string{
		"host":                        "i.instagram.com",
		"user-agent":                  "REPLACE_WITH_YOUR_INSTAGRAM_USER_AGENT",
		"authorization":               fmt.Sprintf("Bearer IGT:2:%s", sessionID),
		"x-ig-app-locale":             "en_GB",
		"x-ig-device-locale":          "en_GB",
		"x-ig-mapped-locale":          "en_GB",
		"x-pigeon-session-id":         fmt.Sprintf("UFS-%s-0", uuid.New().String()),
		"x-pigeon-rawclienttime":      fmt.Sprintf("%.0f", float64(time.Now().Unix())),
		"x-ig-bandwidth-speed-kbps":   "1940.000",
		"x-ig-bandwidth-totalbytes-b": "390031",
		"x-ig-bandwidth-totaltime-ms": "201",
		"x-bloks-version-id":          "9fc6a7a4a577456e492c189810755fe22a6300efc23e4532268bca150fe3e27a",
		"x-ig-www-claim":              "REPLACE_WITH_YOUR_IG_WWW_CLAIM",
		"x-bloks-is-prism-enabled":    "false",
		"x-bloks-is-layout-rtl":       "false",
		"x-ig-device-id":              uuidVal,
		"x-ig-family-device-id":       data.FamilyDeviceID,
		"x-ig-android-id":             deviceID,
		"x-ig-timezone-offset":        "10800",
		"x-ig-nav-chain":              "SelfFragment:self_profile:2:main_profile:1753632303.529::",
		"x-ig-salt-ids":               "332016044,332020615",
		"x-fb-connection-type":        "WIFI",
		"x-ig-connection-type":        "WIFI",
		"x-ig-capabilities":           "3brTv10=",
		"x-ig-app-id":                 "567067343352427",
		"priority":                    "u=3",
		"accept-language":             "en-GB, en-US",
		"x-mid":                       "REPLACE_WITH_YOUR_X_MID",
		"ig-u-ds-user-id":             userID,
		"ig-intended-user-id":         userID,
		"content-type":                "application/x-www-form-urlencoded; charset=UTF-8",
		"accept-encoding":             "zstd, gzip, deflate",
		"x-fb-http-engine":            "Liger",
		"x-fb-client-ip":              "True",
		"x-fb-server-cluster":         "True",
		"cookie":                      fmt.Sprintf("sessionid=%s; csrftoken=%s", sessionID, csrftoken),
		"connection":                  "keep-alive",
	}

	signedBodyData := map[string]interface{}{
		"_uid":  userID,
		"_uuid": uuidVal,
	}
	signedBodyJSON, _ := json.Marshal(signedBodyData)

	payload := url.Values{
		"signed_body": {fmt.Sprintf("SIGNATURE.%s", string(signedBodyJSON))},
	}

	client := &http.Client{}
	req, _ := http.NewRequest("POST", "https://i.instagram.com/api/v1/accounts/set_public/", strings.NewReader(payload.Encode()))
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}

func setAccountPrivate(chatID int64) bool {
	data := userData[chatID]
	if data == nil {
		return false
	}

	uuidVal := data.UUID
	if uuidVal == "" {
		uuidVal = uuid.New().String()
	}

	deviceID := data.AndroidID
	if deviceID == "" {
		deviceID = generateDeviceID(fmt.Sprintf("%f", rand.Float64()))
	}

	userID := data.UserID
	sessionID := data.Session
	csrftoken := data.CSRFToken

	headers := map[string]string{
		"host":                         "i.instagram.com",
		"accept-language":              "en-GB, en-US",
		"authorization":                fmt.Sprintf("Bearer IGT:2:%s", sessionID),
		"content-type":                 "application/x-www-form-urlencoded; charset=UTF-8",
		"ig-intended-user-id":          userID,
		"ig-u-ds-user-id":              userID,
		"priority":                     "u=3",
		"x-bloks-is-layout-rtl":        "false",
		"x-bloks-is-prism-enabled":     "true",
		"x-bloks-prism-button-version": "0",
		"x-bloks-version-id":           "9fc6a7a4a577456e492c189810755fe22a6300efc23e4532268bca150fe3e27a",
		"x-fb-client-ip":               "True",
		"x-fb-connection-type":         "WIFI",
		"x-fb-friendly-name":           "IgApi: accounts/set_private/",
		"x-fb-server-cluster":          "True",
		"x-ig-android-id":              deviceID,
		"x-ig-app-id":                  "567067343352427",
		"x-ig-app-locale":              "en_GB",
		"x-ig-bandwidth-speed-kbps":    "2948.000",
		"x-ig-bandwidth-totalbytes-b":  "4472505",
		"x-ig-bandwidth-totaltime-ms":  "1662",
		"x-ig-client-endpoint":         "AccountPrivacyOptionFragment:account_privacy_option",
		"x-ig-capabilities":            "3brTv10=",
		"x-ig-connection-type":         "WIFI",
		"x-ig-device-id":               uuidVal,
		"x-ig-device-locale":           "en_GB",
		"x-ig-family-device-id":        data.FamilyDeviceID,
		"x-ig-mapped-locale":           "en_GB",
		"x-ig-nav-chain":               "SelfFragment:self_profile:2:main_profile:1753632231.594::",
		"x-ig-timezone-offset":         "10800",
		"x-ig-www-claim":               "REPLACE_WITH_YOUR_IG_WWW_CLAIM",
		"x-mid":                        "REPLACE_WITH_YOUR_X_MID",
		"x-pigeon-rawclienttime":       fmt.Sprintf("%.0f", float64(time.Now().Unix())),
		"x-pigeon-session-id":          fmt.Sprintf("UFS-%s-0", uuid.New().String()),
		"x-tigon-is-retry":             "False",
		"accept-encoding":              "zstd",
		"user-agent":                   "Instagram 309.1.0.41.113 Android (35/15; 420dpi; 1080x2340; samsung; SM-A556E; a55x; s5e8845; en_GB; 541635890)",
		"x-fb-http-engine":             "MNS",
		"cookie":                       fmt.Sprintf("sessionid=%s; csrftoken=%s", sessionID, csrftoken),
		"connection":                   "keep-alive",
	}

	reqTags, _ := json.Marshal(map[string]interface{}{
		"network_tags": map[string]interface{}{
			"product":          "567067343352427",
			"purpose":          "fetch",
			"surface":          "undefined",
			"request_category": "api",
			"retry_attempt":    "0",
		},
	})
	headers["x-fb-request-analytics-tags"] = string(reqTags)

	signedBodyData := map[string]interface{}{
		"_uid":                            userID,
		"_uuid":                           uuidVal,
		"send_approved_friendships_notif": "false",
	}
	signedBodyJSON, _ := json.Marshal(signedBodyData)

	payload := url.Values{
		"signed_body": {fmt.Sprintf("SIGNATURE.%s", string(signedBodyJSON))},
	}

	client := &http.Client{}
	req, _ := http.NewRequest("POST", "https://i.instagram.com/api/v1/accounts/set_private/", strings.NewReader(payload.Encode()))
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}

func followUser(chatID int64, userID string) bool {
	data := userData[chatID]
	if data == nil {
		return false
	}

	uuidVal := data.UUID
	if uuidVal == "" {
		uuidVal = uuid.New().String()
	}

	deviceID := data.AndroidID
	if deviceID == "" {
		deviceID = generateDeviceID(fmt.Sprintf("%f", rand.Float64()))
	}

	myUserID := data.UserID
	sessionID := data.Session
	csrftoken := data.CSRFToken

	headers := map[string]string{
		"host":                        "i.instagram.com",
		"x-ig-app-locale":             "en_GB",
		"x-ig-device-locale":          "en_GB",
		"x-ig-mapped-locale":          "en_GB",
		"x-pigeon-session-id":         fmt.Sprintf("UFS-%s-0", uuid.New().String()),
		"x-pigeon-rawclienttime":      fmt.Sprintf("%.0f", float64(time.Now().Unix())),
		"x-ig-bandwidth-speed-kbps":   "1627.000",
		"x-ig-bandwidth-totalbytes-b": "1873867",
		"x-ig-bandwidth-totaltime-ms": "1017",
		"x-bloks-version-id":          "9fc6a7a4a577456e492c189810755fe22a6300efc23e4532268bca150fe3e27a",
		"x-ig-www-claim":              "REPLACE_WITH_YOUR_IG_WWW_CLAIM",
		"x-bloks-is-prism-enabled":    "false",
		"x-bloks-is-layout-rtl":       "false",
		"x-ig-device-id":              uuidVal,
		"x-ig-family-device-id":       data.FamilyDeviceID,
		"x-ig-android-id":             deviceID,
		"x-ig-timezone-offset":        "10800",
		"x-ig-nav-chain":              "ExploreFragment:explore_popular:3:main_search:1753632772.503::",
		"x-fb-connection-type":        "WIFI",
		"x-ig-connection-type":        "WIFI",
		"x-ig-capabilities":           "3brTv10=",
		"x-ig-app-id":                 "567067343352427",
		"priority":                    "u=3",
		"user-agent":                  "Instagram 309.1.0.41.113 Android (35/15; 420dpi; 1080x2340; samsung; SM-A556E; a55x; s5e8845; en_GB; 541635890)",
		"accept-language":             "en-GB, en-US",
		"authorization":               fmt.Sprintf("Bearer IGT:2:%s", sessionID),
		"x-mid":                       "REPLACE_WITH_YOUR_X_MID",
		"ig-u-ds-user-id":             myUserID,
		"ig-u-rur":                    fmt.Sprintf("LDC,%s,%d:REPLACE_WITH_YOUR_RUR_HASH", myUserID, time.Now().Unix()),
		"ig-intended-user-id":         myUserID,
		"content-type":                "application/x-www-form-urlencoded; charset=UTF-8",
		"accept-encoding":             "zstd, gzip, deflate",
		"x-fb-http-engine":            "Liger",
		"x-fb-client-ip":              "True",
		"x-fb-server-cluster":         "True",
		"cookie":                      fmt.Sprintf("sessionid=%s; csrftoken=%s", sessionID, csrftoken),
		"connection":                  "keep-alive",
	}

	signedBodyData := map[string]interface{}{
		"user_id":          userID,
		"radio_type":       "wifi-none",
		"_uid":             myUserID,
		"device_id":        deviceID,
		"_uuid":            uuidVal,
		"nav_chain":        "ExploreFragment:explore_popular:3:main_search:1753632772.503::",
		"container_module": "profile",
	}
	signedBodyJSON, _ := json.Marshal(signedBodyData)

	payload := url.Values{
		"signed_body": {fmt.Sprintf("SIGNATURE.%s", string(signedBodyJSON))},
	}

	client := &http.Client{}
	url := fmt.Sprintf("https://i.instagram.com/api/v1/friendships/create/%s/", userID)
	req, _ := http.NewRequest("POST", url, strings.NewReader(payload.Encode()))
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}

func acceptInstagramTerms(chatID int64) bool {
	data := userData[chatID]
	if data == nil {
		return false
	}

	sessionID := data.Session

	headers := map[string]string{
		"accept":                      "*/*",
		"accept-encoding":             "gzip, deflate, br",
		"accept-language":             "en-US,en;q=0.9",
		"content-length":              "76",
		"content-type":                "application/x-www-form-urlencoded",
		"cookie":                      fmt.Sprintf("sessionid=%s", sessionID),
		"origin":                      "https://www.instagram.com",
		"referer":                     "https://www.instagram.com/terms/unblock/?next=/api/v1/web/fxcal/ig_sso_users/",
		"sec-ch-prefers-color-scheme": "light",
		"sec-ch-ua":                   `"Not?A_Brand";v="8", "Chromium";v="108", "Google Chrome";v="108"`,
		"sec-ch-ua-mobile":            "?0",
		"sec-ch-ua-platform":          `"Windows"`,
		"sec-fetch-dest":              "empty",
		"sec-fetch-mode":              "cors",
		"sec-fetch-site":              "same-origin",
		"user-agent":                  "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36",
		"viewport-width":              "453",
		"x-asbd-id":                   "198387",
		"x-csrftoken":                 "REPLACE_WITH_YOUR_CSRF_TOKEN",
		"x-ig-app-id":                 "936619743392459",
		"x-ig-www-claim":              "REPLACE_WITH_YOUR_IG_WWW_CLAIM",
		"x-instagram-ajax":            "REPLACE_WITH_YOUR_AJAX_ID",
		"x-requested-with":            "XMLHttpRequest",
	}

	data1 := "updates=%7B%22existing_user_intro_state%22%3A2%7D&current_screen_key=qp_intro"
	data2 := "updates=%7B%22tos_data_policy_consent_state%22%3A2%7D&current_screen_key=tos"

	client := &http.Client{}

	// First request
	req1, _ := http.NewRequest("POST", "https://www.instagram.com/web/consent/update/", strings.NewReader(data1))
	for k, v := range headers {
		req1.Header.Set(k, v)
	}

	resp1, err1 := client.Do(req1)
	if err1 != nil {
		return false
	}
	defer resp1.Body.Close()

	body1, _ := io.ReadAll(resp1.Body)

	// Second request
	req2, _ := http.NewRequest("POST", "https://www.instagram.com/web/consent/update/", strings.NewReader(data2))
	for k, v := range headers {
		req2.Header.Set(k, v)
	}

	resp2, err2 := client.Do(req2)
	if err2 != nil {
		return false
	}
	defer resp2.Body.Close()

	body2, _ := io.ReadAll(resp2.Body)

	// Check if either response indicates success
	successResponse := `{"screen_key":"finished","status":"ok"}`
	return strings.Contains(string(body1), successResponse) || strings.Contains(string(body2), successResponse)
}

func handleSessionInput(bot *tgbotapi.BotAPI, chatID int64, sessionID string) {
	valid, username, userID := checkSessionValid(sessionID)
	if valid {
		csrftoken := generateCSRFToken()
		if userData[chatID] == nil {
			userData[chatID] = &UserData{}
		}
		deviceUUID := uuid.New().String()
		userData[chatID].Session = sessionID
		userData[chatID].Username = username
		if username == "" {
			userData[chatID].Username = "(unknown)"
		}
		userData[chatID].UserID = userID
		userData[chatID].DeviceID = deviceUUID
		userData[chatID].FamilyDeviceID = uuid.New().String()
		userData[chatID].AndroidID = generateDeviceID(fmt.Sprintf("%f", rand.Float64()))
		userData[chatID].UUID = deviceUUID
		userData[chatID].CSRFToken = csrftoken

		msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("Successfully logged in as @%s", userData[chatID].Username))
		msg.ReplyMarkup = getLoggedInKeyboard()
		bot.Send(msg)

		delete(userStates, chatID)
	} else {
		msg := tgbotapi.NewMessage(chatID, "Invalid or expired session ID. Please try again.")
		bot.Send(msg)
		delete(userStates, chatID)
	}
}

func handleUsernameInput(bot *tgbotapi.BotAPI, chatID int64, username string) {
	if username == "" {
		msg := tgbotapi.NewMessage(chatID, "Please enter a valid username.")
		bot.Send(msg)
		return
	}
	// Store username and ask for password
	if userData[chatID] == nil {
		userData[chatID] = &UserData{}
	}
	userData[chatID].Username = username
	userStates[chatID] = "waiting_password"

	msg := tgbotapi.NewMessage(chatID, "Please send your password:")
	bot.Send(msg)
}

func handlePasswordInput(bot *tgbotapi.BotAPI, chatID int64, password string) {
	if password == "" {
		msg := tgbotapi.NewMessage(chatID, "Please enter a valid password.")
		bot.Send(msg)
		return
	}

	msg := tgbotapi.NewMessage(chatID, "Attempting to login with credentials...")
	bot.Send(msg)

	// Here you would implement direct API login similar to the Python version
	// For now, we'll just show a placeholder
	msg = tgbotapi.NewMessage(chatID, "Direct login not implemented yet. Please use session ID login.")
	bot.Send(msg)
	delete(userStates, chatID)
}

func handleBioInput(bot *tgbotapi.BotAPI, chatID int64, newBio string) {
	success := changeBio(chatID, newBio)
	var responseText string
	if success {
		responseText = "Bio updated successfully!"
	} else {
		responseText = "Failed to update bio."
	}

	msg := tgbotapi.NewMessage(chatID, responseText)
	bot.Send(msg)
	delete(userStates, chatID)
}

func handleNameInput(bot *tgbotapi.BotAPI, chatID int64, newName string) {
	success := changeName(chatID, newName)
	var responseText string
	if success {
		responseText = "Name updated successfully!"
	} else {
		responseText = "Failed to update name."
	}

	msg := tgbotapi.NewMessage(chatID, responseText)
	bot.Send(msg)
	delete(userStates, chatID)
}

func handlePasswordResetInput(bot *tgbotapi.BotAPI, chatID int64, query string) {
	if query == "" {
		msg := tgbotapi.NewMessage(chatID, "Please enter a valid username or email.")
		bot.Send(msg)
		return
	}

	msg := tgbotapi.NewMessage(chatID, fmt.Sprintf("Sending password reset for: %s", query))
	bot.Send(msg)

	success := sendPasswordReset(query)
	var responseText string
	if success {
		responseText = "Password reset email sent successfully!"
	} else {
		responseText = "Failed to send password reset email."
	}

	finalMsg := tgbotapi.NewMessage(chatID, responseText)
	bot.Send(finalMsg)
	delete(userStates, chatID)
}

func changeBio(chatID int64, newBio string) bool {
	data := userData[chatID]
	if data == nil {
		return false
	}

	uuidVal := data.UUID
	if uuidVal == "" {
		uuidVal = uuid.New().String()
	}

	deviceID := data.AndroidID
	if deviceID == "" {
		deviceID = generateDeviceID(fmt.Sprintf("%f", rand.Float64()))
	}

	userID := data.UserID
	sessionID := data.Session
	csrftoken := data.CSRFToken

	headers := map[string]string{
		"host":                        "i.instagram.com",
		"user-agent":                  "Instagram 309.1.0.41.113 Android (35/15; 420dpi; 1080x2340; samsung; SM-A556E; a55x; s5e8845; en_GB; 541635890)",
		"authorization":               fmt.Sprintf("Bearer IGT:2:%s", sessionID),
		"x-ig-app-locale":             "en_GB",
		"x-ig-device-locale":          "en_GB",
		"x-ig-mapped-locale":          "en_GB",
		"x-pigeon-session-id":         fmt.Sprintf("UFS-%s-0", uuid.New().String()),
		"x-pigeon-rawclienttime":      fmt.Sprintf("%.0f", float64(time.Now().Unix())),
		"x-ig-bandwidth-speed-kbps":   "1400.000",
		"x-ig-bandwidth-totalbytes-b": "187447",
		"x-ig-bandwidth-totaltime-ms": "128",
		"x-bloks-version-id":          "9fc6a7a4a577456e492c189810755fe22a6300efc23e4532268bca150fe3e27a",
		"x-ig-www-claim":              "REPLACE_WITH_YOUR_IG_WWW_CLAIM",
		"x-bloks-is-prism-enabled":    "false",
		"x-bloks-is-layout-rtl":       "false",
		"x-ig-device-id":              uuidVal,
		"x-ig-family-device-id":       data.FamilyDeviceID,
		"x-ig-android-id":             deviceID,
		"x-ig-timezone-offset":        "10800",
		"x-ig-nav-chain":              "SelfFragment:self_profile:2:main_profile:1753631314.5::",
		"x-fb-connection-type":        "WIFI",
		"x-ig-connection-type":        "WIFI",
		"x-ig-capabilities":           "3brTv10=",
		"x-ig-app-id":                 "567067343352427",
		"priority":                    "u=3",
		"accept-language":             "en-GB, en-US",
		"x-mid":                       "REPLACE_WITH_YOUR_X_MID",
		"ig-u-ds-user-id":             userID,
		"ig-intended-user-id":         userID,
		"content-type":                "application/x-www-form-urlencoded; charset=UTF-8",
		"accept-encoding":             "zstd, gzip, deflate",
		"x-fb-http-engine":            "Liger",
		"x-fb-client-ip":              "True",
		"x-fb-server-cluster":         "True",
		"cookie":                      fmt.Sprintf("sessionid=%s; csrftoken=%s", sessionID, csrftoken),
		"connection":                  "keep-alive",
	}

	signedBodyData := map[string]interface{}{
		"_uid":      userID,
		"device_id": deviceID,
		"_uuid":     uuidVal,
		"raw_text":  newBio,
	}
	signedBodyJSON, _ := json.Marshal(signedBodyData)

	payload := url.Values{
		"signed_body": {fmt.Sprintf("SIGNATURE.%s", string(signedBodyJSON))},
	}

	client := &http.Client{}
	req, _ := http.NewRequest("POST", "https://i.instagram.com/api/v1/accounts/set_biography/", strings.NewReader(payload.Encode()))
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}

func changeName(chatID int64, newName string) bool {
	data := userData[chatID]
	if data == nil {
		return false
	}

	uuidVal := data.UUID
	if uuidVal == "" {
		uuidVal = uuid.New().String()
	}

	userID := data.UserID
	sessionID := data.Session

	headers := map[string]string{
		"host":                         "i.instagram.com",
		"accept-language":              "en-GB, en-US",
		"authorization":                fmt.Sprintf("Bearer IGT:2:%s", sessionID),
		"content-type":                 "application/x-www-form-urlencoded; charset=UTF-8",
		"ig-intended-user-id":          userID,
		"ig-u-ds-user-id":              userID,
		"priority":                     "u=3",
		"x-bloks-is-layout-rtl":        "false",
		"x-bloks-is-prism-enabled":     "true",
		"x-bloks-prism-button-version": "0",
		"x-bloks-version-id":           "9fc6a7a4a577456e492c189810755fe22a6300efc23e4532268bca150fe3e27a",
		"x-fb-client-ip":               "True",
		"x-fb-connection-type":         "WIFI",
		"x-fb-friendly-name":           "IgApi: accounts/update_profile_name/",
		"x-fb-server-cluster":          "True",
		"x-ig-android-id":              data.AndroidID,
		"x-ig-app-id":                  "567067343352427",
		"x-ig-app-locale":              "en_GB",
		"x-ig-bandwidth-speed-kbps":    "3012.000",
		"x-ig-bandwidth-totalbytes-b":  "6048717",
		"x-ig-bandwidth-totaltime-ms":  "1201",
		"x-ig-client-endpoint":         "EditFullNameFragment:profile_edit_full_name",
		"x-ig-capabilities":            "3brTv10=",
		"x-ig-connection-type":         "WIFI",
		"x-ig-device-id":               uuidVal,
		"x-ig-device-locale":           "en_GB",
		"x-ig-family-device-id":        data.FamilyDeviceID,
		"x-ig-mapped-locale":           "en_GB",
		"x-ig-nav-chain":               "SelfFragment:self_profile:3:main_profile:1752979794.20::",
		"x-ig-timezone-offset":         "10800",
		"x-ig-www-claim":               "REPLACE_WITH_YOUR_IG_WWW_CLAIM",
		"x-mid":                        "REPLACE_WITH_YOUR_X_MID",
		"x-pigeon-rawclienttime":       fmt.Sprintf("%.0f", float64(time.Now().Unix())),
		"x-pigeon-session-id":          fmt.Sprintf("UFS-%s-0", uuid.New().String()),
		"x-tigon-is-retry":             "False",
		"accept-encoding":              "zstd",
		"user-agent":                   "Instagram 309.1.0.41.113 Android (35/15; 420dpi; 1080x2340; samsung; SM-A556E; a55x; s5e8845; en_GB; 541635890)",
		"x-fb-http-engine":             "MNS",
		"cookie":                       fmt.Sprintf("sessionid=%s", sessionID),
		"connection":                   "keep-alive",
	}

	reqTags, _ := json.Marshal(map[string]interface{}{
		"network_tags": map[string]interface{}{
			"product":          "567067343352427",
			"purpose":          "fetch",
			"surface":          "undefined",
			"request_category": "api",
			"retry_attempt":    "0",
		},
	})
	headers["x-fb-request-analytics-tags"] = string(reqTags)

	payload := url.Values{
		"first_name": {newName},
		"_uuid":      {uuidVal},
	}

	client := &http.Client{}
	req, _ := http.NewRequest("POST", "https://i.instagram.com/api/v1/accounts/update_profile_name/", strings.NewReader(payload.Encode()))
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}

func sendPasswordReset(query string) bool {
	adid := uuid.New().String()
	guid := uuid.New().String()
	deviceID := generateDeviceID(fmt.Sprintf("%f", rand.Float64()))
	waterfallID := uuid.New().String()

	headers := map[string]string{
		"host":                         "i.instagram.com",
		"accept-language":              "en-GB, en-US",
		"content-type":                 "application/x-www-form-urlencoded; charset=UTF-8",
		"ig-intended-user-id":          "0",
		"priority":                     "u=3",
		"x-bloks-is-layout-rtl":        "false",
		"x-bloks-is-prism-enabled":     "true",
		"x-bloks-prism-button-version": "0",
		"x-bloks-version-id":           "9fc6a7a4a577456e492c189810755fe22a6300efc23e4532268bca150fe3e27a",
		"x-fb-client-ip":               "True",
		"x-fb-connection-type":         "WIFI",
		"x-fb-friendly-name":           "IgApi: accounts/send_recovery_flow_email/",
		"x-fb-server-cluster":          "True",
		"x-ig-android-id":              deviceID,
		"x-ig-app-id":                  "567067343352427",
		"x-ig-app-locale":              "en_GB",
		"x-ig-bandwidth-speed-kbps":    "1627.000",
		"x-ig-bandwidth-totalbytes-b":  "232803",
		"x-ig-bandwidth-totaltime-ms":  "143",
		"x-ig-client-endpoint":         "user_password_recovery",
		"x-ig-capabilities":            "3brTv10=",
		"x-ig-connection-type":         "WIFI",
		"x-ig-device-id":               guid,
		"x-ig-device-locale":           "en_GB",
		"x-ig-family-device-id":        uuid.New().String(),
		"x-ig-mapped-locale":           "en_GB",
		"x-ig-nav-chain":               "SelfFragment:self_profile:3:main_profile:1753632938.508::",
		"x-ig-timezone-offset":         "10800",
		"x-ig-www-claim":               "0",
		"x-mid":                        "REPLACE_WITH_YOUR_X_MID",
		"x-pigeon-rawclienttime":       fmt.Sprintf("%.0f", float64(time.Now().Unix())),
		"x-pigeon-session-id":          fmt.Sprintf("UFS-%s-1", uuid.New().String()),
		"x-tigon-is-retry":             "False",
		"accept-encoding":              "zstd",
		"user-agent":                   "Instagram 309.1.0.41.113 Android (35/15; 420dpi; 1080x2340; samsung; SM-A556E; a55x; s5e8845; en_GB; 541635890)",
		"x-fb-http-engine":             "MNS",
		"x-fb-rmd":                     "state=URL_ELIGIBLE",
		"connection":                   "keep-alive",
	}

	reqTags, _ := json.Marshal(map[string]interface{}{
		"network_tags": map[string]interface{}{
			"product":          "567067343352427",
			"purpose":          "fetch",
			"surface":          "undefined",
			"request_category": "api",
			"retry_attempt":    "0",
		},
	})
	headers["x-fb-request-analytics-tags"] = string(reqTags)

	signedBodyData := map[string]interface{}{
		"adid":         adid,
		"guid":         guid,
		"device_id":    deviceID,
		"query":        query,
		"waterfall_id": waterfallID,
	}
	signedBodyJSON, _ := json.Marshal(signedBodyData)

	payload := url.Values{
		"signed_body": {fmt.Sprintf("SIGNATURE.%s", string(signedBodyJSON))},
	}

	client := &http.Client{}
	req, _ := http.NewRequest("POST", "https://i.instagram.com/api/v1/accounts/send_recovery_flow_email/", strings.NewReader(payload.Encode()))
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == 200
}
