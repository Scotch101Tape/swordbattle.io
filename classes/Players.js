/*
Players class
Holds the players and provides convenient methods
*/

const SessionObject = require("./SessionObject");

class Players extends SessionObject {
  constructor(session) {
    // Maps socket id to player
    this.players = {};

    // List of dead player's ids
    this.deadPlayers = [];

    // See ./SessionObject.js
    super(session);
  }

  // Gets the player from the id
  // If the id does not correspond to a player it returns undefined
  getPlayer(id) {
    if (id in this.players) {
      return this.players[id]
    } else {
      return undefined
    }
  }

  // Maps an id to a player
  setPlayer(id, player) {
    this.players[id] = player;
  }

  // Gets rid of the player that corresponds with the id
  // If the id corresponds with a player, it will push the id to deadPlayers
  deletePlayer(id) {
    if (id in this.players) {
      delete this.players[id];
      this.deadPlayers.push(id);
    }
  }

  // Returns whether the id corresponds with a player
  has(id) {
    return id in this.players;
  }

  // Shouldn't ever be used because of how JS works, this is obsolette (At least i think so I won't get rid of it yet.........)
  updatePlayer(player) {
    this.setPlayer(player.id, player);
  }

  // Removes players from this.players who are listed in this.deadplayers
  clean() {
    Object.filter = (obj, predicate) => 
    Object.keys(obj)
          .filter( key => predicate(obj[key]) )
          .reduce( (res, key) => (res[key] = obj[key], res), {} );
    this.players = Object.filter(this.players,(p => !this.deadPlayers.includes(p.id)));
  }

  // Returns the players as a list
  asList() {
    return Object.values(this.players)
  }
}

module.exports = Players;