/*
Session class
Defines a session of swordbattle.io
*/


// Modules
const Players = require("./Players")
const Player = require("./Player")
const AiPlayer = require("./AiPlayer")
const { sql } = require("../database");
const filter = require("leo-profanity")
const Coin = require("./Coin")
const Chest = require("./Chest")
const { v4: uuidv4 } = require("uuid");

// The session class
class Session {
  Status = {
    Exiting: 0,
    Running: 1,
    Entering: 2,
  }

  constructor(io, room, connectedToDatabase, configure) {
    // The io instance from socket.io
    this.io = io;
    
    // Max coins allowed in the session
    this.maxCoins = configure.maxCoins;

    // Max chests allowed in the session
    this.maxChests = configure.maxChests;

    // Max Ai players allowed in the session
    this.maxAiPlayers = configure.maxAiPlayers;

    // Max players allowed in the session
    this.maxPlayers = configure.maxPlayers;

    // Exp needed to level up
    // (This means it is possible to have sessions with different leveling up ways)
    this.levels = configure.levels;

    // List of coins
    this.coins = [];

    // List of chests
    this.chests = [];

    // The socket.io room
    this.room = room;

    // If the session will connect to the database
    // If set to false, this mean that coins collected in this session will not save
    this.connectedToDatabase = connectedToDatabase;

    // Players
    this.players = new Players(this);

    // The status
    // Entering until there is a player
    // Running until cleanup is run
    // Exiting until it is gone
    this.status = Session.Status.Entering

    // The last time that the server sent out a PSA about where all the chests and coins are
    this.lastChestSend = Date.now()
    this.lastCoinSend = Date.now()
  }

  // To be fired 30 times per second (every 1000/30ms)
  async tick() {
    // If the server is entering, don't do the tick
    if (this.status == Session.Status.Entering) {
      return
    }

    // clean up the playerlist
    this.players.clean();

    // Add a new coin if the maxCoins are not reached
    if (this.coins.length < this.maxCoins) {
      this.coins.push(new Coin());
      this.io.to(this.room).emit("coin", this.coins[this.coins.length - 1]);
    }

    // Add a new chest if the maxChests are not reached
    if(this.chests.length < this.maxChests) {
      this.chests.push(new Chest());
      this.io.to(this.room).emit("chest", this.chests[this.chests.length - 1]);
    }

    // Add a new ai player if there are real players and a random condition is met
    if (this.realPlayerCount() > 0 && this.aiPlayerCount() < this.maxAiPlayers && Math.random() <= 0.01) {
      // Create the ai player
      var id = uuidv4();
      var aiPlayer = new AiPlayer(id);
      console.log(`AI Player Joined -> ${aiPlayer.name}`);

      // Add it to the list
      this.players.setPlayer(id, aiPlayer);

      // Emit a new player
      this.io.to(this.room).emit("new", aiPlayer);
    }

    // If its been 10 seconds since the last chest PSA
    if (Date.now() - this.lastChestSend >= 10 * 1000) {
      // Emit the chests
      this.io.to(this.room).emit("chests", this.chests);

      // Update the last time it happened
      this.lastChestSend = Date.now();
    }

    // Get all the sockets
    var sockets = await this.io.in(this.room).fetchSockets();

    // Check for join packets and kick if one is not sent
    sockets.forEach((b) => {
      if (!b.joined && Date.now() - b.joinTime > 10000) {
        b.emit(
          "ban",
          "You have been kicked for not sending JOIN packet. <br>This is likely due to slow wifi.<br>If this keeps happening, try restarting your device."
        );
        b.disconnect();
      }
    });

    // Health regen
    this.players.asList().forEach((player) => {
      if (player) {
        // Update the player values
        player.updateValues()
        //   player.moveWithMouse(players)

        // Tick ai players
        if(player.ai) {
          [this.coins, this.chests] = player.tick(this.coins, this.io, this.levels, this.chests);
        }

        // if its been x seconds since player got hit, regen then every 100 ms
        if (
          Date.now() - player.lastHit > player.healWait &&
          Date.now() - player.lastRegen > 75 &&
          player.health < player.maxHealth
        ) {
          // Heal ❤️
          player.lastRegen = Date.now();
          player.health += (player.health / 100) * player.healAmount;
        }

        // Might be unessicary
        // Not sure
        // But this updates the player in the playerList
        this.players.updatePlayer(player);

        //emit player data to all clients
        // Keeping in mind this is in a loop over all the players
        // So it goes
        // for player in players:
        //   for socket in sockets:
        //     *function below*
        sockets.forEach((socket) => {
          // If the player does not have a send object, well, ig its over so gg
          if (!player.getSendObj()) console.log("gg");

          // If the socket does not correspond with the player
          if (player.id != socket.id) {
            // Emit "player" with the send object
            socket.emit("player", player.getSendObj());
          } else { // If the socket corresponds with the player
            // emit "me" with the player (NOT the send object)
            socket.emit("me", player);
            // If its been a second since the last coin send
            if(Date.now() - this.lastCoinSend >= 1000) {
              // Emit the coins the are next to the player
              socket.emit("coins", this.coins.filter((coin) => coin.inRange(player)));
            }
          }
        });
      }
    });
  
    // reset the time when the last coin send was
    if(Date.now() - this.lastCoinSend >= 1000) {
      this.lastCoinSend = Date.now();
    }
  }
  

  // Connect the socket to the session
  // This includes creating the player for the socket and connecting all the events, etc
  async connectSocket(socket, name, options) {
    // Connect the socket to the session room
    socket.join(this.room)

    // Clean the name
    var name;
    if (!tryverify) {
      try {
        name = filter.clean(options.name.substring(0, 16));
      } catch (e) {
        name = options.name.substring(0, 16);
      }
    } else {
      var accounts = await sql`select * from accounts where secret=${options.name}`;
      if (!accounts[0]) {
        socket.emit(
          "ban",
          "Invalid secret, please try logging out and relogging in"
        );
        socket.disconnect();
        return;
      }
      var name = accounts[0].username;
    }
    options.name = name;

    // Create the player
    var player = new Player(socket.id, options.name)
    player.updateValues()
    if ("movementMode" in options) {
      player.movementMode = options.movementMode;
    }
    if (options.tryverify) {
      player.verified = true;
      player.skin = accounts[0].skins.selected;
    }

    // Emit the new player to the rest of the players
    socket.to(this.room).emit("new", player)

    // Emit the rest of the players to the player if there are players other than thePlayer in the session
    var allPlayers = this.players.asList()
    if (allPlayers.filter(p => p.id != player.id).length > 0) {
      socket.emit("players", allPlayers)
    }

    //TODO: Make coins emit only within range (not sure if this is done ill just leave this)
    // Emit the coins
    socket.emit("coins", this.coins.filter((coin) => coin.inRange(player)));

    // Emit the chests
    socket.emit("chests", this.chests);

    // Emit the levels
    socket.emit("levels", this.levels);
    
    // Set that the socket is joined
    socket.joined = true;

    // Connect the socket to events
    events: {
      // When the player wants to evolve
      socket.on("evolve", (eclass) => {
        // If player is not in player list, return
        if(!this.players.has(socket.id)) {
          return socket.emit("refresh")
        }

        // Get the player
        var player = this.players.getPlayer(socket.id);

        // Some more sanity checks and then do the evolution
        if(player.evolutionQueue && player.evolutionQueue.length > 0 && player.evolutionQueue[0].includes(eclass.toLowerCase())) {
          eclass = eclass.toLowerCase();
          player.evolutionQueue.shift();
          var evo = evolutions[eclass];
          console.log(`${player.name} evolved to ${eclass}`);
              
          player.evolutionData = {default: evo.default(), ability: evo.ability()};
          player.evolution = evo.name;
          player.updateValues();
          socket.emit("refresh");
          return;
        }
      });

      // When the player want to use an ability
      socket.on("ability", () => {
        // If player is not in player list, return
        if (this.players.has(socket.id)) {
          return socket.emit("refresh")
        }

        // Get the player
        var player = this.players.getPlayer(socket.id);

        // If the player has an evolution
        if(player.evolution != "") {
          // check if ability activated already
          if(player.ability <= Date.now()) {
            // Activate ability
            player.ability = evolutions[player.evolution].abilityCooldown + evolutions[player.evolution].abilityDuration + Date.now();
            console.log(`${player.name} activated ability`);
            socket.emit("ability", [evolutions[player.evolution].abilityCooldown , evolutions[player.evolution].abilityDuration, Date.now()]);
          }
        }
      });

      // When the player has a new mousePos
      socket.on("mousePos", (mousePos) => {
        if (this.players.has(socket.id)) {
          var player = this.players.getPlayer(socket.id);
          player.mousePos = mousePos;        
        } else {
          socket.emit("refresh");
        }
      });

      //  When the players mouse is down or up
      socket.on("mouseDown", (down) => {
        if (this.players.has(socket.id)) {
          var player = this.players.getPlayer(socket.id);
          if (player.mouseDown == down) return;
          [this.coins, this.chests] = player.down(down, this.coins, this.io, this.chests);
        } else { 
          socket.emit("refresh");
        }
      });

      // When the player wants to move
      socket.on("move", (controller) => {
        if (!controller) return;
        try {
          if (this.players.has(socket.id)) {
            var player = this.players.getPlayer(socket.id);
            player.move(controller);
            coins = player.collectCoins(this.coins, this.io, this.levels);
          }
        } catch (e) {
          console.log(e);
        }
      });

      // When a player wants to chat
      socket.on("chat", (msg) => {
        msg = msg.trim().replace(/\\/g, "\\\\");
        if (msg.length > 0) {
          /// Trim the message
          if (msg.length > 35) msg = msg.substring(0, 35);

          // Sanity checks
          if (!this.players.has(socket.id) || Date.now() - this.players.getPlayer(socket.id).lastChat < 1000) return;

          // Set the last chat time
          var player = this.players.getPlayer(socket.id);
          player.lastChat = Date.now();
          // PlayerList.setPlayer(socket.id, p); I dont think this needs to be uncommented
          
          // Emit chat
          this.io.to(this.room).emit("chat", {
            msg: filter.clean(msg),
            id: socket.id,
          });
        }
      });

      // I hate this
      // This makes me cry
      // ;(((((
      function clamp(num, min, max) {
        return num <= min ? min : num >= max ? max : num;
      }

      // When the player wants to leave
      socket.on("disconnect", () => {
        // If the server is shutting down ignore this
        if(this.status == Session.Status.Exiting) return;

        // Sanity checks
        if (!this.players.has(socket.id)) return;

        // Get the player
        var player = this.players.getPlayer(socket.id);

        //drop their coins randomly near them
        var drop = [];
        var dropAmount = clamp(Math.round(player.coins*0.8), 10, 20000);
        var dropped = 0;
        while (dropped < dropAmount) {
          var r = player.radius * player.scale * Math.sqrt(Math.random());
          var theta = Math.random() * 2 * Math.PI;
          var x = player.pos.x + r * Math.cos(theta);
          var y = player.pos.y + r * Math.sin(theta);
          var remaining = dropAmount - dropped;
          var value = remaining > 50 ? 50 : (remaining > 10 ? 10 : (remaining > 5 ? 5 : 1));

          this.coins.push(
            new Coin({
              x: clamp(x, -(map/2), map/2),
              y: clamp(y, -(map/2), map/2),
            }, value)
          );

          dropped += value;
          drop.push(this.coins[this.coins.length - 1]);
        }

        // Emit the new coins
        this.io.to(this.room).emit("coin", drop, [player.pos.x, player.pos.y]);    

        sql`INSERT INTO games (name, coins, kills, time, verified) VALUES (${player.name}, ${player.coins}, ${player.kills}, ${Date.now() - player.joinTime}, ${player.verified})`;

        // Delete the player
        this.players.deletePlayer(socket.id);

        // Emit the player left
        socket.to(this.room).emit("playerLeave", socket.id);
      });
    }

    // Move from entering to running when the first player is connected
    if (this.status == Status.Entering) {
      this.status = Status.Running
    }
  }

  // Returns the amount of real players in the session
  realPlayerCount() {
    return this.players.asList().filter(player => !player.ai).length
  }

  // Return the amount of ai players in the session
  aiPlayerCount() {
    return this.players.asList().filter(player => player.ai).length
  }

  // Return the total players in the session
  totalPlayerCount() {
    return this.player.asList().length
  }

  // Clean yourself up you slob
  cleanup() {
    this.status = Session.Status.Exiting
  }
}

module.exports = Session;