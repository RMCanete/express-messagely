/** User class for message.ly */

const db = require("../db");
const bcrypt = require("bcrypt");
const { BCRYPT_WORK_FACTOR, DB_URI, SECRET_KEY } = require("../config");
const ExpressError = require("../expressError");



/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({username, password, first_name, last_name, phone}) { 
    try {
      const { username, password, first_name, last_name, phone } = req.body;
      const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
      const result = await db.query(
        `INSERT INTO users (username, password, first_name, last_name, phone, join_at, last_login_at)
          VALUES ($1, $2, $3, $4, $5, current_timestamp, current_timestamp)
          RETURNING username`,
          [username, hashedPassword, first_name, last_name, phone]
      );
      return res.json(result.row[0]);
    } catch (err) {
      return next(err);
    }
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) { 
    try {
      const { username, password } = req.body;
      const result = await db.query(
        `SELECT password FROM users WHERE username = $1`,
        [username]);
      let user = result.row[0];

      if (user) {
        if (await bcrypt.compare(password, user.password) === true) {
          let token = jwt.sign({ username }, SECRET_KEY);
          return true;
        } else return false;
      }
      throw new ExpressError("Invalid user/password", 400);
    } catch (err) {
      return next(err);
    }
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) { 
    try {
      const { username } = req.body;
      const result = await db.query(
        `UPDATE users
          SET last_login_at = current_timestamp
          WHERE username = $1
          RETURNING username`,
        [username]);
      if (!result.rows[0]) {
        throw new ExpressError("No user with that username", 404)
      } 
      return result.rows[0];
    }
      catch (err) {
        return next(err);
      }
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() { 
    try {
      const result = await db.query(
        `SELECT username, first_name, last_name, phone FROM users`);
      return result.row[0];
    } catch (err) {
      return next(err);
    }
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    try {
      const { username } = req.body;
      const result = await db.query(
        `SELECT username, first_name, last_name, phone, join_at, last_login_at FROM users
        WHERE username = $1, [username]`);
      if (!result.rows[0]) {
        throw new ExpressError("No user with that username", 404)
      } 
      return result.row[0];
    } catch (err) {
      return next(err);
    }
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) { 
    try {
      const { username } = req.body;
      const result = await db.query(
        `SELECT messages.id, messages.to_username, message.body, message.sent_at, message.read_at,
        user.first_name, user.last_name, user.phone 
        FROM messages
        JOIN users ON message.username = user.username
        WHERE username = $1, [username]
        RETURNING messages.id, messages.to_username, message.body, message.sent_at, message.read_at,
        user.first_name, user.last_name, user.phone`);
      if (!result.rows[0]) {
        throw new ExpressError("No user with that username", 404)
      } 
      return result.row[0];
    } catch (err) {
      return next(err);
    }
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) { 
    try {
      const { username } = req.body;
      const result = await db.query(
        `SELECT messages.id, messages.from_username, message.body, message.sent_at, message.read_at,
        user.first_name, user.last_name, user.phone 
        FROM messages
        JOIN users ON message.username = user.username
        WHERE username = $1, [username]
        RETURNING messages.id, messages.from_username, message.body, message.sent_at, message.read_at,
        user.first_name, user.last_name, user.phone`);
      if (!result.rows[0]) {
        throw new ExpressError("No user with that username", 404)
      } 
      return result.row[0];
    } catch (err) {
      return next(err);
    }
  }
}


module.exports = User;