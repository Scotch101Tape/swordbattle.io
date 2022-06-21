/*
Sessions class
Holds the sessions and provides convenient methods
*/

// Modules
const Session = require("./Session");
const evolutions = require("./evolutions");

// Do some modifaction to the levels
const levels = require("../levels.json").map((level, index, array) => {
  // Set start
  if(index == 0) {
		level.start = 0;
	} else {
    level.start = array[index - 1].coins;
	}

  // Replace evolution string with evolution class
  if ("evolutions" in level) {
    level.evolutions = level.evolutions.map((evolutionString) => {
      return evolutions[evolutionString];
    });
  }

  return level;
});

class Sessions {
  // The name of the main room
  static MAIN_ROOM = "main";

  // The amount of time a session can be without players before it is removed (in ms)
  static NO_PLAYER_TIME_LIMIT = 30 * 1000;

  constructor(io) {
    // The main room is always created

    // Maps room to password
    this.passwords = {};

    // Maps room to last time they had players
    this.lastHadPlayers = {};

    // Maps room to session
    this.sessions = {
      [Sessions.MAIN_ROOM]: new Session(io, Sessions.MAIN_ROOM_NAME, true,{
          maxCoins: 2000,
          maxChests: 20,
          maxAiPlayers: 20,
          maxPlayers: 50,
          levels: levels
      })
    };

    console.log(Sessions.MAIN_ROOM);

    // The io instance
    this.io = io;
  }

  // Adds a session with the password
  addSession(session, password) {
    // A session CANNOT be named the same as the main room
    console.assert(session.room != Sessions.MAIN_ROOM, `A session cannot have the room name of ${Sessions.MAIN_ROOM}`);

    this.passwords[session.room] = password;
    this.sessions[session.room] = session;
    this.lastHadPlayers[session.room] = Date.now();
  }

  // Removes a session
  removeSession(session) {
    session.cleanup();

    delete this.sessions[session];
    delete this.passwords[session];
    delete this.lastHadPlayers[session];
  }

  // Returns whether the password is correct for the room
  isCorrectPassword(room, password) {
    return this.passwords[room] == password;
  }

  // Removes any sessions with zero players for more than the time limit
  clean() {
    this.forEachSession((session) => {
      // If there is no players and the session is starting up
      if (session.realPlayerCount == 0 && session.status != Session.Status.Entering) {
        // If the session has had no players for NO_PLAYER_TIME_LIMIT then remove the session
        if (Date.now() - this.lastHadPlayers[session.room] > Sessions.NO_PLAYER_TIME_LIMIT) {
          this.removeSession(session);
        }
      } else {
        this.lastHadPlayers[session.room] = Date.now();
      }
    });
  }

  // Returns whether the session 
  has(room) {
    return room in this.sessions;
  }

  // Returns the session that corresponds with room 
  session(room) {
    return this.sessions[room];
  }

  // Returns all the players in all the sessions
  allPlayers() {
    var allPlayers = [];

    for (const session of Object.values(this.sessions)) {
      for (const player of session.players.asList()) {
        allPlayers.push(player);
      }
    }

    return allPlayers;
  }

  allSockets() {
    var sockets = [];
    for (const player of this.allPlayers()) {
      sockets.push(player.socket);
    }
    return sockets;
  }

  sessionsInList() {
    return Object.values(this.sessions);
  }
}

module.exports = Sessions;
