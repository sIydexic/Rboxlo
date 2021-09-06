var exports = module.exports = {}

const compare = require("safe-compare")
const crypto = require("crypto")
const fetch = require("node-fetch")
const fs = require("fs")
const httpBuildQuery = require("http-build-query")
const moment = require("moment")
const path = require("path")
const validator = require("validator")
const zxcvbn = require("zxcvbn")

const locker = require(path.join(__dirname, "base", "locker"))
const sql = require(path.join(__dirname, "base", "sql"))
const util = require(path.join(__dirname, "base", "util"))

/**
 * Time in seconds until a ping "times out" (user is no longer doing said activity)
 */
const PING_TIMEOUT = 30

/**
 * Time in seconds until a user will stop being given anti-robot challenges
 */
const CHALLENGE_EXPIRY = 7200

/**
 * Time in seconds until a long term session expires
 */
const LONG_TERM_SESSION_EXPIRY = (86400 * 7) // One week

/**
 * Generates a default avatar array with the classic "noob" style
 * 
 * @param {boolean} stringified Whether to return array as JSON-encoded or not (default: true)
 * 
 * @returns {(string|array)} Either an array or a stringified version of it, depending on what stringified is set to
 */
function generateDefaultAvatar (stringified = true) {
    let avatar = {
        "colors": {
            "head": "24",          // Bright yellow
            "torso": "23",         // Bright blue
            "left_arm": "24",      // Bright yellow
            "right_arm": "24",     // Bright yellow
            "left_leg": "119",     // Br. yellowish green
            "right_leg": "119"     // Br. yellowish green
        },
        "package": "r6_default",
        "head": "",
        "face": "",
        "hats": {},
        "gears": {},
        "tshirt": "",
        "shirt": "",
        "pants": "",
        "r15_animations": {
            "emotes": {},
            "walk": "",
            "run": "",
            "fall": "",
            "jump": "",
            "swim": "",
            "climb": "",
            "idle": ""
        },
        "r15_avatar_scaling": {
            "width": "1.0000",
            "height": "1.0000",
            "head": "1.0000",
            "depth": "1.00",
            "proportion": "0.0000",
            "body_type": "0.0000"
        },
        "avatar_type": "r6"
    }

    if (stringified) {
        avatar = JSON.stringify(avatar)
    }

    return avatar
}

/**
 * Generates the default preferences array
 * 
 * @param {boolean} stringified Whether to return array as JSON-encoded or not (default: true)
 * 
 * @returns {(string|array)} Either an array or a stringified version of it, depending on what stringified is set to
 */
function generateDefaultPreferences (stringified = true) {
    let preferences = {
        "blurb": `Hi! I'm new to ${global.rboxlo.name}.`,
        "theme": 0, // Light theme
        "2fa": false
    }

    if (stringified) {
        return JSON.stringify(preferences)
    }

    return preferences
}

/**
 * Generates the default global permissions tree
 * 
 * @param {boolean} stringified Whether to return array as JSON-encoded or not (default: true)
 * 
 * @returns {(string|array)} Either an array or a stringified version of it, depending on what stringified is set to
 */
function generateDefaultPermissions (stringified = true) {
    let permissions = {
        "places": {
            "creation": true,                    // User can create places
            "watchdog": false,                   // User can access WatchDog
            "playerlist_icon_asset_id": -1,      // User's playerlist icon asset id (-1 for none)
            "see_job_id": false,                 // User is allowed to see Job IDs for place servers
            "global_modification": {
                "description": false,            // User can modify any place's description
                "title": false,                  // User can modify any place's title
                "thumbnails": false,             // User can upload, or disapprove of any place's thumbnail(s)
                "download_level": false,         // User is allowed to download any place's level
                "icon": false,                   // User can upload or disapprove of any place's icon
                "shutdown_servers": false        // User is allowed to shut down any place's server(s)
            }
        },
        "servers": {
            "creation": true,                    // User can host their own server
            "global_modification": {
                "description": false,            // User is allowed to modify any self-hosted servers description
                "title": false,                  // User is allowed to modify any self-hosted servers title
                "delete": false                  // User is allowed to delete any self-hosted server
            }
        },
        "economy": {
            "create_assets": true,               // User can create catalog items
            "sell_assets": true,                 // User can sell their created items
            "upload_trusted_assets": {
                "hat": false,                    // User can create a trusted hat
                "gear": false,                   // User can create a trusted gear
                "face": false                    // User can create a trusted face
            },
            "global_modification": {
                "limiteds": false,               // User can modify any item to become a limited
                "uniques": false,                // User can modify any item to become a unique
                "price": false,                  // User can modify any items price
                "thumbnail": false,              // User can modify any items thumbnail
                "name": false,                   // User can modify any items name
                "description": false             // User can modify any items description
            },
            "delete_assets": false,              // User can delete any asset
            "force_render_assets": false,        // User can render, or re-render item thumbnails
            "can_comment_on_assets": true        // User is allowed to comment on assets
        },
        "users": {
            "moderation": {
                "general_ban": false,            // User can hand out normal bans for any other user
                "poison_ban": false,             // User can hand out poison bans for any other user
                "ip_ban": false,                 // User can hand out IP bans for any other user
                "delete_user": false             // User can completely delete any other users account
            },
            "see_money": false,                  // User can view any other users money
            "modify_money": false,               // User can modify any other users money
            "force_render": false,               // User can render, or re-render any other users avatar thumbnail
            "modify_avatar": false,              // User can modify any other users avatar
            "update_own_biography": true,        // User can modify their own bio
            "send_friend_requests": true,        // User can send friend requests to other users
            "send_messages": true                // User can send private messages to other users
        },
        "forums": {
            "delete_threads": false,             // User can delete any other users threads
            "sticky_threads": false,             // User can sticky any other users threads
            "lock_threads": false,               // User can lock any other users threads
            "edit_posts": false,                 // User can edit any other users posts
            "prune_user_posts": false,           // User can perform a complete prune on a users forum history
            "creation": {
                "categories": false,             // User can create categories
                "hubs": false,                   // User can create hubs
                "threads": true,                 // User can create threads
                "replies": true                  // User can create replies
            }
        },
        "site_wide": {
            "create_banners": false,             // User is allowed to create a site-wide banner
            "maintenance": false                 // User is allowed to put the entire website under maintenance
        },
        "can_modify_user_permissions": false,    // User is allowed to modify any other users permissions
        "formal_title": {
            "shown": false,                      // Users formal title is shown
            "title": "User",                     // Users formal title
            "hex_color": "39C0ED"                // Users formal title color in uppercase hexadecimal form
        }
    }

    if (stringified) {
        permissions = JSON.stringify(permissions)
    }

    return permissions
}

/**
 * Generates a default sign in history containing only one entry, which is the users current IP address and user agent
 * 
 * @param {string} ip User's IP address
 * @param {string} userAgent User's agent
 * @param {boolean} stringified Whether to return array as JSON-encoded or not (default: true)
 *
 * @returns {(string|array)} Either an array or a JSON-encoded string, depending on what stringified is set to
 */
function generateDefaultSignInHistory (ip, userAgent, stringified = true) {
    let history = {}
    history[moment().unix()] = { "ip": ip, "userAgent": userAgent }

    if (stringified) {
        history = JSON.stringify(history)
    }

    return history
}

/**
 * Appends to a user's sign in history with a given user agent and IP address
 *
 * @param {string} userId ID of the user who's history is being signed into
 * @param {string} ip User's IP address
 * @param {string} userAgent User's agent
 */
async function appendToSignInHistory(userId, ip, userAgent) {
    let history = (await sql.run("SELECT `sign_in_history` FROM `users` WHERE `id` = ?", userId))[0]
    history = locker.decrypt(history.sign_in_history)

    history[moment().unix()] = { "ip": ip, "userAgent": userAgent }
    
    history = JSON.stringify(history)
    history = locker.encrypt(history)

    await sql.run("UPDATE `users` SET `sign_in_history` = ? WHERE `id` = ?", [history, userId])
}

/**
 * Generates a default last ping history
 * 
 * @param {boolean} stringified Whether to return array as JSON-encoded or not (default: true)
 * 
 * @returns {(string|array)} Either an array or a stringified version of it, depending on what stringified is set to
 */
function generateDefaultLastPing (stringified = true) {
    let fakeTimedOutPing = (moment().unix() - PING_TIMEOUT)
    let lastPing = {
        website: moment().unix(),
        client: fakeTimedOutPing,
        studio: fakeTimedOutPing,
        hosting: fakeTimedOutPing
    }

    if (stringified) {
        lastPing = JSON.stringify(lastPing)
    }

    return lastPing
}

/**
 * Generates an invite key
 * 
 * @returns {string} Generated invite key
 */
function generateInviteKey () {
    return crypto.randomBytes(64).toString("hex")
}

/**
 * Validates an invite key
 * 
 * @param {string} key Invite key to validate
 * 
 * @returns {boolean} If valid key
 */
function validateInviteKey (key) {
    return key.length == 128 && validator.isAlphanumeric(key)
}

/**
 * Runs query on database to find information of a given invite key
 *
 * @param {string} inviteKey The invite key
 * @param {boolean} returnAllColumns If true, returns all columns of the invite key row if it is found (default: false)
 *
 * @returns {(bool|array)} If the invite key was not found, returns FALSE. Otherwise, returns an associative array containing the columns "id", "uses", and "max_uses" of the invite key row. If returnAllColumns is set to TRUE, it will return all columns of the invite key row, including "id", "uses", and "max_uses".
 */
async function getInviteKeyInfo (inviteKey, returnAllColumns) {
    if (!validateInviteKey(inviteKey)) {
        return false
    }

    // SECURITY: Escaping SQL without prepares.
    let columns = (returnAllColumns ? "*" : "`id`, `uses`, `max_uses`")
    let result = await sql.run(`SELECT ${columns} FROM \`invite_keys\` WHERE \`key\` = ?`, inviteKey)

    if (result.length == 0) {
        return false
    }

    return result[0]
}

/**
 * Determines if a user needs a stipend, and if so returns the stipend amount. All resulting stipends are in absolute value
 *
 * @param {number} lastStipendTimestamp Unix timestamp of the users last stipend payment
 * @param {boolean} stackStipends Whether to stack stipends. If they haven't logged in in three days, and this is set to TRUE, it will reward the user with three days worth of stipends. If this isn't set to TRUE, and they haven't logged in in a while, it will return only reward the user with one days worth of stipend. (default: false)
 *
 * @returns {(number|boolean)} Returns the stipend amount if they satisfy the timeout. If they do not, returns FALSE
 */
function getStipend (lastStipendTimestamp, stackStipends = true) {
    if ((moment().unix() - lastStipendTimestamp) >= global.rboxlo.env.STIPEND_TIMEOUT) {
        if (stackStipends) {
            return Math.abs(Math.floor((moment().unix() - lastStipendTimestamp) / global.rboxlo.env.STIPEND_TIMEOUT) * global.rboxlo.env.STIPEND_AMOUNT)
        }

        return Math.abs(global.rboxlo.env.STIPEND_AMOUNT) // their stipend is the project stipend amount
    }

    return false // no stipend required
}

/**
 * Updates a users stipend
 * 
 * @param {number} userId ID of the user whose stipend should be updated
 * @param {bool} stackStipends Whether to stack stipends
 */
async function updateStipend (userId, stackStipends) {
    let user = await sql.run("SELECT `last_stipend_timestamp`, `money` FROM `users` WHERE `id` = ?", userId)
    let result = user[0]
    let stipend = getStipend(result.last_stipend_timestamp, stackStipends)

    if (stipend !== false) {
        await sql.run(
            "UPDATE `users` SET `money` = ?, `last_stipend_timestamp` = ? WHERE `id` = ?",
            [(result.money + stipend), moment().unix(), userId]
        )
    }
}

/**
 * Sets the thumbnail of a user to the default one (noob)
 * 
 * @param {number} userId ID of the user to set
 */
function setDefaultThumbnail (userId) {
    fs.copyFileSync(path.join(global.rboxlo.root, "data", "thumbnails", "users", "0.png"), path.join(global.rboxlo.root, "data", "thumbnails", "users", `${userId}.png`))
}

/**
 * Creates a login attempt
 * 
 * @param {number} threshold Attempt threshold
 * @param {string} userAgent User's useragent
 * @param {string} ip User's IP address
 */
async function createLoginAttempt (threshold, userAgent, ip) {
    let result = await sql.run("SELECT `id`, `attempts`, `amount`, `threshold`, `created_timestamp` FROM `login_attempts` WHERE `ip` = ?", ip)

    if (result.length > 0) {
        let attempt = result[0]
        attempt.attempts = JSON.parse(attempt.attempts)

        attempt.attempts.push({
            "ip": ip,
            "userAgent": userAgent,
            "time": moment().unix()
        })
        attempt.amount += 1

        await sql.run(
            "UPDATE `login_attempts` SET `attempts` = ?, `amount` = ? WHERE `id` = ?",
            [JSON.stringify(attempt.attempts), attempt.amount, attempt.id]
        )
    } else {
        let attempts = [{
            "ip": ip,
            "userAgent": userAgent,
            "time": moment().unix()
        }]
        
        await sql.run(
            "INSERT INTO `login_attempts` (`attempts`, `threshold`, `ip`, `created_timestamp`) VALUES (?, ?, ?, ?)",
            [JSON.stringify(attempts), threshold, ip, moment().unix()]
        )
    }
}

/**
 * Determines if a user needs a captcha challenge because of too many failed sign in attempts
 * 
 * @param {string} ip User's IP address
 * 
 * @returns {boolean} If they need a challenge
 */
exports.needsAuthenticationChallenge = async (ip) => {
    if (!global.rboxlo.env.GOOGLE_RECAPTCHA_ENABLED) {
        return false
    }

    let result = await sql.run("SELECT `id`, `amount`, `threshold`, `created_timestamp` FROM `login_attempts` WHERE `ip` = ?", ip)
    
    if (result.length == 0) {
        return false
    }

    result = result[0]
    if ((moment().unix() - result.created) > CHALLENGE_EXPIRY) {
        await sql.run("DELETE FROM `login_attempts` WHERE `id` = ?", result.id)
        return false
    }

    if (result.amount >= result.threshold) {
        return true
    }

    return false
}

/**
 * Checks a long term session, or deletes one if it has expired
 * 
 * @param {string} content Content of "remember_me" cookie
 * 
 * @returns {(boolean|number)} If succeeded, returns the user ID. Otherwise, returns FALSE
 */
exports.verifyLongTermSession = async (content) => {
    let exploded

    if (content.includes(":")) {
        exploded = content.split(":")
        if (exploded.length != 2) {
            return false
        }
    } else {
        return false
    }

    let selector = exploded[0]
    let validator = exploded[1]

    let result = await sql.run("SELECT `id`, `validator_hash`, `user_id`, `expires_timestamp` FROM `long_term_sessions` WHERE `selector` = ?", selector)
    if (result.length > 0) {
        result = result[0]

        if ((moment().unix() - result.expires_timestamp) >= LONG_TERM_SESSION_EXPIRY) {
            await sql.run("DELETE FROM `long_term_sessions` WHERE `id` = ?", result.id)
            return false
        } else {
            let hash = crypto.createHash("sha256").update(validator).digest("hex")

            // Timing-attack safe comparison
            if (compare(result.validator_hash, hash)) {
                return result.user_id
            }
        }
    }

    return false
}

/**
 * Creates a long term session
 * 
 * @param {string} ip User's IP address
 * @param {string} userAgent User's useragent
 * @param {number} userId User ID to create a long term session of
 * @param {boolean} returnSession Whether to return the selector, validator and expiry (default: false)
 * 
 * @returns {(string|undefined)} Returns the session details if returnSession is true
 */
exports.createLongTermSession = async (ip, userAgent, userId, returnSession = false) => {
    let selector = crypto.randomBytes(8).toString("hex")
    let validator = crypto.randomBytes(64).toString("hex")
    let expires = moment().unix() + LONG_TERM_SESSION_EXPIRY

    await sql.run(
        "INSERT INTO `long_term_sessions` (`selector`, `validator_hash`, `user_id`, `created_timestamp`, `expires_timestamp`, `ip`, `user_agent`) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [selector, crypto.createHash("sha256").update(validator).digest("hex"), userId, moment().unix(), expires, ip, userAgent]
    )

    if (returnSession) {
        return {
            "selector": selector,
            "validator": validator,
            "expires": LONG_TERM_SESSION_EXPIRY
        }
    }
}

/**
 * Formats a long term session into a way that can be stored in a cookie
 * 
 * @param {array} session Session containing "selector" and "validator" elements
 * 
 * @returns {string} Formatted long term session in "selector:validator" form
 */
exports.formatLongTermSession = (session) => {
    return `${session.selector}:${session.validator}`
}

/**
 * Gets the necessary session information for a user
 * 
 * @param {number} userId User ID to get information of
 * 
 * @returns {array} Array containing session information
 */
exports.getNecessarySessionInfoForUser = async (userId) => {
    let result = await sql.run(
        "SELECT `id`, `username`, `created_timestamp`, `last_stipend_timestamp`, `last_ping`, `permissions`, `preferences`, `avatar`, `email_verified`, `is_banned`, `current_ban_article`, `money` FROM `users` WHERE `id` = ?",
        userId
    )
    let user = result[0]

    user.permissions = JSON.parse(user.permissions)
    user.avatar = JSON.parse(user.avatar)
    user.preferences = JSON.parse(user.preferences)
    user.last_ping = JSON.parse(user.last_ping)

    return user
}

/**
 * Updates the last ping time for a user
 * 
 * @param {string} application Application to update for
 * @param {number} userId ID of the user to update
 */
exports.updateLastPing = async (application, userId) => {
    let user = await sql.run("SELECT `last_ping` FROM `users` WHERE `id` = ?", userId)
    let pings = JSON.parse((user[0]).last_ping)
    pings[application] = moment().unix()

    sql.run("UPDATE `users` SET `last_ping` = ? WHERE `id` = ?", [JSON.stringify(pings), userId])
}

/**
 * Authenticates a user
 * 
 * @param {string} information Array containing elements "username" and "password"
 * @param {string} ip User's IP address
 * @param {string} userAgent User agent
 * @param {number} antiRobot Anti robot threshold attempts, if set to something it will activate needsAuthenticationChallenge (default: false)
 * @param {boolean} rememberMe Remember user (default: false)
 * @param {boolean} setLastPing Sets the last ping for website (default: true)
 * @param {boolean} stipendWillUpdate Updates their stipend if need be (default: true)
 * @param {boolean} stackStipends Stacks stipends if updating (default: false)
 * @param {boolean} allowEmailSignIn Allows "username" field to be the E-Mail address of the user (default: false)
 * @param {boolean} signInHistoryAppend Appends to sign-in history if valid password (default: true)
 * 
 * @returns {array} Returns "success" meaning valid authenticated and a array "targets" if there was an error
 */
exports.authenticate = (information, ip, userAgent, antiRobot = false, rememberMe = false, setLastPing = true, stipendWillUpdate = true, stackStipends = false, allowEmailSignIn = false, signInHistoryAppend = true) => {
    return new Promise(async (resolve, reject) => {
        let response = {"success": false, targets: {}}

        // 1: Create login attempt
        if (antiRobot !== false) {
            await createLoginAttempt(antiRobot, userAgent, ip)
        }
    
        // 2: Username and password simple validation
        {
            if (!response.targets.hasOwnProperty("username") && (!information.hasOwnProperty("username") || information.username.length == 0)) {
                response.targets.username = "In order to sign in, you need to specify a username."
            }
    
            if (!response.targets.hasOwnProperty("password") && (!information.hasOwnProperty("password") || information.password.length == 0)) {
                response.targets.password = "In order to sign in, you need to specify a password."
            }
        }
    
        // 3: Database validation
        {
            if (!response.targets.hasOwnProperty("password") && !response.targets.hasOwnProperty("username")) {
                // Set the default error message for username to "Invalid username or password."
                // If we succeed, we are not resolving with the response variable
                response.targets.username = "Invalid username or password."
    
                let query = "SELECT `id`, `password_hash` FROM `users` WHERE `username` = ?"
                let parameters = information.username
    
                if (allowEmailSignIn) {
                    query += " OR `email_blind_index` = ?"
                    parameters = [information.username, await locker.blind(information.username)]
                }
                let result = await sql.run(query, parameters)

                if (result.length > 0) {
                    let user = result[0]
                    if (await locker.passwordVerify(user.password_hash, information.password)) {
                        let out = { success: true, userId: user.id }

                        if (rememberMe) {
                            let longTermSession = await exports.createLongTermSession(ip, userAgent, user.id, true)
                            out.longTermSession = longTermSession
                        }
                        
                        if (signInHistoryAppend) await appendToSignInHistory(user.id, ip, userAgent)
                        if (setLastPing) await exports.updateLastPing("website", user.id)
                        if (stipendWillUpdate) await updateStipend(user.id, stackStipends)

                        resolve(out)
                    }
                }
            }
        }

        resolve(response)
    })
}

/**
 * Creates a user account
 * 
 * @param {array} information Must contain elements "username", "password", "email", and "confirmed_password"
 * @param {string} ip User's IP address
 * @param {string} userAgent User's agent
 * @param {boolean} generateThumbnail Creates a default "noob" thumbnail for this user if the account gets created and if set to true (default: true)
 * 
 * @returns {array} Returns "success" meaning valid registration and a array "targets" if there was an error and field "id" user id if valid create (success)
 */
exports.createAccount = (information, ip, userAgent, generateThumbnail = true) => {
    return new Promise(async (resolve, reject) => {
        let response = {"success": false, targets: {}}

        // 1: Password, username, and E-Mail simple validation
        {
            if (!response.targets.hasOwnProperty("username") && (!information.hasOwnProperty("username"))) {
                response.targets.username = "Please choose a username."
            }
    
            if (!response.targets.hasOwnProperty("username") && !validator.isAlphanumeric(information.username)) {
                response.targets.username = "Only alphanumeric usernames are allowed."
            }
    
            if (!response.targets.hasOwnProperty("username") && information.username.length < 3) {
                response.targets.username = "Your username has to be at least 3 characters or more."
            }
    
            if (!response.targets.hasOwnProperty("username") && information.username.length > 20) {
                response.targets.username = "Your username has to be less than 20 characters."
            }
    
            if (!response.targets.hasOwnProperty("email") && (!information.hasOwnProperty("email") || information.email.length == 0)) {
                response.targets.email = "Please enter a E-Mail address."
            }
    
            if (!response.targets.hasOwnProperty("email")) {
                information.email = util.filterEmail(information.email)
                if (information.email === false) {
                    response.targets.email = "Invalid E-Mail address."
                }
            }
    
            if (!response.targets.hasOwnProperty("email") && information.email.length > 128) {
                response.targets.email = "Your E-Mail address cannot exceed 128 characters."
            }
    
            if (!response.targets.hasOwnProperty("password1") && (!information.hasOwnProperty("password1") || information.password1.length == 0)) {
                response.targets.password1 = "Please choose a password."
            }
            
            if (!response.targets.hasOwnProperty("password1") && information.password1.length <= 12) {
                response.targets.password1 = "Your password must be longer than 12 characters."
            }
    
            if (!response.targets.hasOwnProperty("password1") && information.password1.length > 4096) {
                response.targets.password1 = "Your password must be shorter than 4096 characters."
            }
    
            if (!response.targets.hasOwnProperty("password1")) {
                let secure = zxcvbn(information.password1)
                if (secure.score < 3) {
                    let message = "Your password is not secure enough."
    
                    if (secure.feedback.hasOwnProperty("suggestions") && secure.feedback.suggestions.length > 0) {
                        message += ` ${secure.feedback.suggestions[0]}`
                    }
    
                    response.targets.password1 = message
                }
            }
    
            if (!response.targets.hasOwnProperty("password2") && (!information.hasOwnProperty("password2") || information.password2.length == 0)) {
                response.targets.password2 = "You must confirm your password."
            }
    
            if ((!response.targets.hasOwnProperty("password1") && !response.targets.hasOwnProperty("password2")) && (information.password1 !== information.password2)) {
                response.targets.password2 = "Passwords do not match."
            }
        }
    
        // 2: Database validation
        {
            var stop

            // TODO: These can be cached somehow.
            if (!response.targets.hasOwnProperty("username")) {
                let result = await sql.run("SELECT 1 FROM `users` WHERE `username` = ?", information.username)
                if (result.length > 0) {
                    response.targets.username = "That username is currently taken by another user."
                }
            }
    
            if (!response.targets.hasOwnProperty("email")) {
                let result = await sql.run("SELECT 1 FROM `users` WHERE `email_blind_index` = ?", await locker.blind(information.email))
                if (result.length > 3) {
                    response.targets.email = "Too many accounts exist with this E-Mail address."
                }
            }

            stop = (response.targets.hasOwnProperty("username") || response.targets.hasOwnProperty("email") || response.targets.hasOwnProperty("password1") || response.targets.hasOwnProperty("password2"))
        }

        // 3: Create account
        if (!stop) {
            // 3a: Invite key check
            if (global.rboxlo.env.PROJECT_PRIVATE_INVITE_KEY) {
                if (!response.targets.hasOwnProperty("invite_key") && (!information.hasOwnProperty("invite_key") || information.invite_key.length == 0)) {
                    response.targets.invite_key = `You need an invite key in order to register on ${global.rboxlo.name}.`
                }
    
                if (!response.targets.hasOwnProperty("invite_key")) {
                    let key = getInviteKeyInfo(information.invite_key)
    
                    if (key === false) {
                        response.targets.invite_key = "Invite key does not exist."
                    } else if (key.uses >= key.max_uses) {
                        response.targets.invite_key = "That invite key has already been used."
                    }
    
                    if (!response.targets.hasOwnProperty("invite_key")) {
                        var inviteKey = key.id
                    }
                }
    
                stop = (stop || response.targets.hasOwnProperty("invite_key"))
            }
    
            // 3b: Actually create account
            if (!stop) {
                if (global.rboxlo.env.PROJECT_PRIVATE_INVITE_KEY && inviteKey !== undefined) {
                    // TODO: This routine and invite key SQL table structure

                    // The user is registering via an invite key. Mark the invite key as used.
                }
                
                // Prepare values for user row entry
                let password = await locker.passwordHash(information.password1)
                let emailCiphertext = locker.encrypt(information.email)
                let emailBlind = await locker.blind(information.email)
    
                let joindate = moment().unix()
                let last_stipend_timestamp = moment().unix()

                let lastPing = generateDefaultLastPing()
                let permissions = generateDefaultPermissions()
                let preferences = generateDefaultPreferences()
                let avatar = generateDefaultAvatar()
    
                // Blind our IP and encrypt the sign in history
                let signInHistory = locker.encrypt(generateDefaultSignInHistory(ip, userAgent))
                let ipBlind = await locker.blind(ip)
                
                // Insert row for this user
                await sql.run(
                    "INSERT INTO `users` (`username`, `password_hash`, `email_ciphertext`, `email_blind_index`, `created_timestamp`, `last_stipend_timestamp`, `last_ping`, `permissions`, `preferences`, `avatar`, `sign_in_history`, `register_ip_blind_index`, `2fa_secret`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    [information.username, password, emailCiphertext, emailBlind, joindate, last_stipend_timestamp, lastPing, permissions, preferences, avatar, signInHistory, ipBlind, ""]
                )
    
                // Fetch ID
                let result = (await sql.run("SELECT `id` FROM `users` WHERE `username` = ?", information.username))[0]
                
                // Response
                response.userId = result.id
                response.success = true
    
                if (generateThumbnail) setDefaultThumbnail(result.id)
            }
        }

        resolve(response)
    })
}

/**
 * Verifies a reCaptcha response
 * 
 * @param {string} ip User's IP Address
 * @param {string} response reCaptcha Response
 * 
 * @returns {boolean} If the Google API confirmed it 
 */
exports.verifyCaptcha = async (ip, response) => {
    if (!global.rboxlo.env.GOOGLE_RECAPTCHA_ENABLED) {
        return true
    }
    
    let url = "https://www.google.com/recaptcha/api/siteverify"
    let query = {
        secret: global.rboxlo.env.GOOGLE_RECAPTCHA_PRIVATE_KEY,
        remoteip: ip,
        response: response
    }

    var success = false

    await fetch(url, {
        method: "POST",
        headers: {
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body: httpBuildQuery(query)
    })
    .then(res => res.json())
    .then(json => { success = (json.success === true) })

    return success
}

// TODO for these two functions (authenticated, loggedOut)
// Figure out why changing the order breaks

/**
 * Checks if a user is authenticated for routes, if not, redirects to login page
 */
exports.authenticated = (req, res, next) => {
    if (req.session.rboxlo.hasOwnProperty("user")) {
        return next()
    }

    req.session.rboxlo.redirect = `${req.protocol}://${req.get("host")}${req.originalUrl}`
    res.redirect("/login")
}

/**
 * Checks if a user is not authenticated for routes, if they ARE authenticated, it just puts them in their dashboard
 */
exports.loggedOut = (req, res, next) => {
    if (!req.session.rboxlo.hasOwnProperty("user")) {
        return next()
    }

    res.redirect("/my/dashboard")
}

/**
 * Checks if a user exists
 * 
 * @param {number} userID ID of user to verify
 * @returns {boolean} If user exists
 */
exports.exists = async (userID) => {
    let result = await sql.run("SELECT 1 FROM `users` WHERE `id` = ?", userID)
    return result.length > 0
}