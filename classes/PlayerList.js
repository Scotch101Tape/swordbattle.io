class PlayerList {
  static MAIN_ROOM_NAME = "main"
  static rooms = {
    [PlayerList.MAIN_ROOM_NAME]: {
      players: {},
      deadPlayers: [],
    }
  }
  static allPlayers = {}

  static newRoom(roomName) {
    this.rooms[roomName] = {
      players: {},
      deadPlayers: []
    }
  }

  static getPlayer(id) {
    if(this.allPlayers.hasOwnProperty(id)) return this.allPlayers[id];
    else return undefined;
  }
  static setPlayer(id, player) {
    this.allPlayers[id] = player;
    this.rooms[player.roomName].players[id] = player;
  }
  static deletePlayer(id) {
    if(this.allPlayers.hasOwnProperty(id)) {
      let deleteingPlayer = this.allPlayers[id]
      delete this.allPlayers[id];
      delete this.rooms[deleteingPlayer.roomName].players[id];
      this.rooms[deleteingPlayer.roomName].deadPlayers.push(id);
     //  console.log("kjifjgkjifjgkjifjgkjifjgkjifjgkjifjgkjifjgkjifjgvvvvvvvvvvv")
     // ok gautum... 🤣 - scotch101tape
    }
  }
  static has(id) {
    return this.allPlayers.hasOwnProperty(id);
  }
  static updatePlayer(player) {
    this.setPlayer(player.id, player)
  }
  static clean() {
    for (const roomName in this.rooms) {
      const room = this.rooms[roomName]
      for (const playerId in room.players) {
        if (room.deadPlayers.includes(playerId)) {
          delete room.players[playerId]
          delete this.allPlayers[playerId]
        }
      }
    }
  }
}

module.exports = PlayerList;
