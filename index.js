/*
index.js
The main file for the server
This is the first file that is run
*/

const express = require("express");
const https = require("https");
var http = require("http");
require("dotenv").config();
const { Server } = require("socket.io");
const app = express();
var emailValidator = require("email-validator");
const bcrypt = require("bcrypt");
var uuid = require("uuid");
var fs = require("fs");
var process = require("process");

// When the server is exiting and preping to shut down, this turns to "exiting"
var serverState = "running";

// The size of the map
var map = 10000;
//var cors = require("cors");

// The servers
var server;
var httpsserver;

//console.log(fs.readFileSync("/etc/letsencrypt/live/test.swordbattle.io/fullchain.pem"))

// Encryption stuff
var usinghttps = false;
if (process.env.USEFISHYSSL === "true") {
  usinghttps = true;
  var options = {
    key: fs.readFileSync(
      "/etc/letsencrypt/live/us2.swordbattle.io/privkey.pem"
    ),
    cert: fs.readFileSync(
      "/etc/letsencrypt/live/us2.swordbattle.io/fullchain.pem"
    ),
  };
  httpsserver = https.createServer(options, app).listen(443);
}

// Set up the server
server = http.createServer(app);

//server = http.createServer(app);

// Modules, very messy but it works and is really not important to code structure so dont touch it
const axios = require("axios").default;
var filter = require("leo-profanity");
const moderation = require("./moderation");
const { v4: uuidv4 } = require("uuid");
const {recaptcha} = require("./config.json");
var passwordValidator = require("password-validator");
var schema = new passwordValidator();
app.use(express.json());
// Add properties to it
schema
  .is()
  .min(5, "Password has to be at least 5 chars") // Minimum length 5
  .is()
  .max(20, "Password cant be longer than 20 chars") // Maximum length 20
  .has()
  .not()
  .spaces(undefined, "Password cant contain spaces"); // Should not have spaces

// Modules
const Player = require("./classes/Player");
const Coin = require("./classes/Coin");
const Chest = require("./classes/Chest");
const AiPlayer = require("./classes/AiPlayer");
const PlayerList = require("./classes/PlayerList");
const Session = require("./classes/Session");
const evolutions = require("./classes/evolutions")
const { sql } = require("./database");
const { config } = require("dotenv");

// Contains info on cosmetics
const cosmetics = JSON.parse(fs.readFileSync("./cosmetics.json"));

// Sanity checks for when password and username are passed in a http request
const checkifMissingFields = (req,res,next) => {
  if(typeof req.body!=="object" || typeof req.body.password !== "string" || typeof req.body.username !== "string" || typeof req.body.captcha !== "string") {	
      res.send({error: "Missing fields"});
      return;
  }
  next();
};

// Set up socket.io
const io = new Server(usinghttps ? httpsserver : server, {
  cors: { origin: "*" },
});

// Utility function
function getRandomInt(min, max) {
  return min + Math.floor(Math.random() * (max - min + 1));
}

// If it is in production, then use rate limiter
var production = true;
if (production) {
	const rateLimit = require("express-rate-limit");
	const limiter = rateLimit({
		windowMs: 60 * 1000, // 1 min
		max: 300, // limit each IP to 52 requests per min 
		//Edited from 500 to 300 requests per min. bc 500 is too much and people can abuse API, in clonclusion it is not working as you want it to work. #FixByLuis
	});
	app.use(limiter);
}

// Idk, something, not sure, dont touch
app.set("trust proxy", true);
/*
app.use((req, res, next) => {
  console.log("URL:", req.url);
  console.log("IP:", req.ip);
  next();
});*/

// Get the levels
const levels = JSON.parse(fs.readFileSync("./levels.json")).map((level, index, array) => {
  // Set start
  if(index == 0) {
		Object.assign({start: 0}, level);
	} else {
		Object.assign({start: array[index - 1].coins}, level);
	}

  // Replace evolution string with evolution class
  if ("evolution" in level) {
    level.evolution = evolutions[level.evolution];
  }

  return level;
})

// Get moderation for app
moderation.start(app);

app.use(function (req, res, next) {
  // Website you wish to allow to connect
  res.setHeader("Access-Control-Allow-Origin", "*");

  // Request methods you wish to allow
  res.setHeader(
    "Access-Control-Allow-Methods",
    "GET, POST, OPTIONS, PUT, PATCH, DELETE"
  );

  // Request headers you wish to allow
  res.setHeader(
    "Access-Control-Allow-Headers",
    "X-Requested-With,content-type"
  );

  // Set to true if you need the website to include cookies in the requests sent
  // to the API (e.g. in case you use sessions)
  res.setHeader("Access-Control-Allow-Credentials", true);

  // Pass to next layer of middleware
  next();
});

/*******************************************************************************************************/
/* App paths *******************************************************************************************/
/*******************************************************************************************************/

// / leads to dist directory
app.use("/", express.static("dist"));

// /assets leads to assets directory
app.use("/assets", express.static("assets"));

// /api/buy allows for buying cosmetic
app.post("/api/buy", async (req, res) => {
  //read cosmetics.json
  var cosmetics = JSON.parse(fs.readFileSync("./cosmetics.json"));

  //get user data
  var secret = req.body.secret;
  var item = req.body.item;

  // Santiy check for if they sent an item
  if (!item || item == "undefined") {
    res.status(400).send("No item specified");
    return;
  }

  // Try to find item in the cosmetics
  var item = cosmetics.skins.find((e) => e.name == item);

  // Santiy check for if the item exists
  if (!item) {
    res.status(400).send("Item not found");
    return;
  }

  var acc;
  // Make sure the secret exists
  if (secret && secret != "undefined") {
    // Get the account
    var account = await sql`select skins,coins,username from accounts where secret=${secret}`;

    // Make sure account exists
    if (account[0]) {
      acc = account[0];
      var yo =
        await sql`SELECT sum(coins) FROM games WHERE lower(name)=${acc.username.toLowerCase()} AND verified='true';`;
      acc.bal = yo[0].sum + acc.coins;

      // Check if the item is already bought
      if (acc.skins.collected.includes(item.name)) {
        res.status(400).send("Skin already owned");
        return;
      }

      // Check if the item is too many coins for the player trying to buy it
      if (acc.bal < item.price) {
        res.status(406).send("Not enough coins");
        return;
      }

      // Update the balence and skins of the player
      var newbal = acc.coins - item.price;
      var newskins = acc.skins;
      newskins.collected.push(item.name);

      // Update the database
      await sql`UPDATE accounts SET skins=${JSON.stringify(
        newskins
      )},coins=${newbal} WHERE secret=${secret}`;

      // Send a sucess back
      res.send("Success");
      return;
    } else {
      // Error for bad secret
      res.status(400).send("Invalid secret");
      return;
    }
  } else {
    // Error for no secret
    res.status(400).send("No secret provided");
    return;
  }
});

// /api/equip allows for equiping a skin
app.post("/api/equip", async (req, res) => {
  // get data from request
  var secret = req.body.secret;
  var item = req.body.item;

  // Sanity check for if the item was sent
  if (!item || item == "undefined") {
    res.status(400).send("No item specified");
    return;
  }
  
  // Trying to find the item specified
  var item = cosmetics.skins.find((e) => e.name == item);

  // Sanity check for if the item exists
  if (!item) {
    res.status(400).send("Item not found");
    return;
  }

  var acc;
  // Make sure secret was sent
  if (secret && secret != "undefined") {
    // Get the account associated with the secret
    var account = await sql`select skins,coins,username from accounts where secret=${secret}`;

    // Make sure the account exists
    if (account[0]) {
      acc = account[0];
      // Make sure the player owns the skin
      if (acc.skins.collected.includes(item.name)) {
        // Update which skin is equipped
        var newskins = acc.skins;
        newskins.selected = item.name;

        // Updata database
        await sql`UPDATE accounts SET skins=${JSON.stringify(
          newskins
        )} WHERE secret=${secret}`;

        // Return success
        res.send("Success");
        return;
      } else {
        // Error if the item is not owned
        res.status(400).send("Item not owned");
        return;
      }
    } else {
      // Error if the secret is bad
      res.status(400).send("Invalid secret");
      return;
    }
  } else {
    // Error if no secret
    res.status(400).send("No secret provided");
    return;
  }
});

// /api/signup allows for players to sign up
// the checkifMissingFields middleware runs sanity checks to make sure that the correct information is in the body
app.post("/api/signup",checkifMissingFields, async (req, res) => {
  // Seems redundant as checkifMissingFields just did this, though I will not mess with it
	if(typeof req.body!=="object" || typeof req.body.password !== "string" || typeof req.body.username !== "string") {	
		res.send({error: "Missing fields"});
		return;
	}

  // Make sure the email is valid
	if(req.body.email && req.body.email.length > 30) {
		res.send({error: "Email too long"});
		return;
	}
	if(req.body.email && !emailValidator.validate(req.body.email)) {
		res.send({error: "Invalid email"});
		return;
	}

  // Make sure the password is valid
	if(!schema.validate(req.body.password)) {
		res.send({error:schema.validate(req.body.password, { details: true })[0].message});
		return;
	}
  
  // Make sure the username is valid
	var username = req.body.username;
	if(username.length >= 20) {
		res.send({error: "Username has to be shorter than 20 characters"});
		return;
	}
	if(username.charAt(0) == " " || username.charAt(username.length - 1) == " ") {
		res.send({error: "Username can't start or end with a space"});
		return;
	}
	if(username.includes("  ")) {
		res.send({error: "Username can't have two spaces in a row"});
		return;
	}
	var regex = /^[a-zA-Z0-9!@"$%&:';()*\+,;\-=[\]\^_{|}<>~` ]+$/g;
	if(!username.match(regex)) {
		res.send({error: "Username can only contain letters, numbers, spaces, and the following symbols: !@\"$%&:';()*\+,-=[\]\^_{|}<>~`"});
		return;
	}
	var containsProfanity = filter.check(username);
	if(containsProfanity) {
		res.send({error: "Username contains a bad word!\nIf this is a mistake, please contact an admin."});
		return;
	}
	var exists = await sql`select exists(select 1 from accounts where lower(username)=lower(${username}))`;
	if (exists[0].exists) {
		res.send({error: "Username already taken"});
		return;
	}

  // Encrpyt the username and password and put it into the database
	bcrypt.hash(req.body.password, 10, (err, hash) => {
		if (err) {
      // Send error if anything fails
			res.status(500).send({error:"Internal server error"});
			return;
		}

    // Create a secret for the account
		var secret = uuid.v4();

    // Update the database
		sql`insert into accounts(username, password, email, secret, skins, lastlogin) values(${username}, ${hash}, ${req.body.email}, ${secret}, ${JSON.stringify({collected: ["player"], selected: "player"})}, ${Date.now()})`;

    // Send the secret back
		res.send({secret: secret});
	});
});

app.post("/api/login",checkifMissingFields, async (req, res) => { 


	async function doit() {
	var username = req.body.username;
	var password = req.body.password;
	var account = await sql`select * from accounts where lower(username)=lower(${username})`;

	if(!account[0]) {
		res.send({error: "Invalid username"});
		return;
	}

	const match = await bcrypt.compare(password, account[0].password);
	if(!match) {
		res.send({error: "Invalid password"});
		return;
	}
	
	res.send(account[0]);
	}
	var send = {
		secret: process.env.CAPTCHASECRET,
		response: req.body.captcha,
		remoteip: req.headers["x-forwarded-for"] || req.socket.remoteAddress 
	};
	if(recaptcha) {
		axios
			.post(
				"https://www.google.com/recaptcha/api/siteverify?" +
	  new URLSearchParams(send)
			)
			.then(async (f) => {
				f = f.data;
				if (!f.success) {
					res.status(403).send("Captcha failed " +  f["error-codes"].toString());
					return;
				}
				if (f.score < 0.3) {
					res.status(403).send("Captcha score too low");
					return;
				}
				doit();
			});
	}else doit();
});

app.post("/api/loginsecret", async (req, res) => {
  if (!req.body || !req.body.secret || req.body.captcha == undefined) {
    res.send({ error: "Missing secret or captcha" });
    return;
  }

  async function doit() {
    var secret = req.body.secret;

    var account = await sql`select * from accounts where secret=${secret}`;

    if (!account[0]) {
      res.send({ error: "Invalid secret" });
      return;
    }

    res.send(account[0]);
  }
  var send = {
    secret: process.env.CAPTCHASECRET,
    response: req.body.captcha,
    remoteip: req.headers["x-forwarded-for"] || req.socket.remoteAddress,
  };
  if (recaptcha) {
    axios
      .post(
        "https://www.google.com/recaptcha/api/siteverify?" +
          new URLSearchParams(send)
      )
      .then(async (f) => {
        f = f.data;
        if (!f.success) {
          res.status(403).send("Captcha failed " + f["error-codes"].toString());
          return;
        }
        if (f.score < 0.3) {
          res.status(403).send("Captcha score too low");
          return;
        }
        doit();
      });
  } else doit();
});

app.get("/skins", async (req, res) => {
  res.redirect("/shop");
});

app.get("/shop", async (req, res) => {
  //read cosmetics.json
  var cosmetics = JSON.parse(fs.readFileSync("./cosmetics.json"));

  //get user data
  var secret = req.query.secret;
  var acc;
  if (secret != "undefined") {
    var account =
      await sql`select skins,coins,username from accounts where secret=${secret}`;
    if (account[0]) {
      acc = account[0];
      var yo =
        await sql`SELECT sum(coins) FROM games WHERE lower(name)=${acc.username.toLowerCase()} AND verified='true';`;
      acc.bal = yo[0].sum + acc.coins;
    }
  }

  res.render("shop.ejs", {
    cosmetics: cosmetics,
    account: acc,
    secret: secret,
  });
});

app.get("/leaderboard", async (req, res) => {
  //SELECT * from games where EXTRACT(EPOCH FROM (now() - created_at)) < 86400 ORDER BY coins DESC LIMIT 10

  //var lb= await sql`SELECT * FROM games ORDER BY coins DESC LIMIT 13`;
  var type = ["coins", "kills", "time", "xp"].includes(req.query.type)
    ? req.query.type
    : "coins";
  var duration = ["all", "day", "week", "xp"].includes(req.query.duration)
    ? req.query.duration
    : "all";
  if (type !== "xp") {
    if (duration != "all") {
      var lb =
        await sql`SELECT * from games where EXTRACT(EPOCH FROM (now() - created_at)) < ${
          duration == "day" ? "86400" : "608400"
        } ORDER BY ${sql(type)} DESC, created_at DESC LIMIT 23`;
    } else {
      var lb = await sql`SELECT * from games ORDER BY ${sql(
        type
      )} DESC, created_at DESC LIMIT 23`;
    }
  } else {
    if (duration != "all") {
      var lb =
        await sql`select name,(sum(coins)+(sum(kills)*100)) as xp from games where verified = true and EXTRACT(EPOCH FROM (now() - created_at)) < ${
          duration == "day" ? "86400" : "608400"
        } group by name order by xp desc limit 23`;
    } else {
      var lb =
        await sql`select name,(sum(coins)+(sum(kills)*100)) as xp from games where verified = true group by name order by xp desc limit 23`;
    }
    lb = lb.map((x) => {
      x.verified = true;
      return x;
    });
  }

  console.log(type, duration);
  res.render("leaderboard.ejs", { lb: lb, type: type, duration: duration });
});

app.get("/settings", async (req, res) => {
  res.send(
    "I'm still working on this page.<br><br>For now, if you want to change password, or change your username, please email me at<br>gautamgxtv@gmail.com"
  );
});

app.get("/:user", async (req, res, next) => {
  var user = req.params.user;
  var dbuser =
    await sql`SELECT * from accounts where lower(username)=lower(${user})`;
  if (!dbuser[0]) {
    next();
  } else {
    var yo =
      await sql`SELECT * FROM games WHERE lower(name)=${user.toLowerCase()} AND verified='true';`;

    /*
		TODO

		SELECT A.dt,
		B.NAME,
		B.COINS
		FROM
		(
		SELECT distinct(DATE_ACTUAL) as dt FROM d_date
			WHERE DATE_ACTUAL>='2022-01-01'
		order by date_actual asc
		) A
		
		LEFT outer JOIN 
		(
		SELECT
		NAME,
		CREATED_AT::DATE AS PLAYED_DATE,
		sum(COINS) as coins
		FROM
		GAMES GMS
		WHERE VERIFIED=TRUE
		group by name,created_at::Date
		) B
		ON A.dt=B.PLAYED_DATE
		WHERE NAME='Dooku'
		ORDER BY A.dt ASC
	
*/

    var stats = await sql`
		select a.dt,b.name,b.xp,b.kills from
		(
		select distinct(created_at::date) as Dt from games where created_at >= ${
      dbuser[0].created_at
    }::date-1 
		order by created_at::date 
		) a
		left join
		(
		  SELECT name,created_at::date as dt1,(sum(coins)+(sum(kills)*100)) as xp,sum(kills) as kills ,sum(coins) as coins,
		  sum(time) as time FROM games WHERE verified='true' and lower(name)=${user.toLowerCase()} group by name,created_at::date
		) b on a.dt=b.dt1 order by a.dt asc
		`;
    var lb =
      await sql`select name,(sum(coins)+(sum(kills)*100)) as xp from games where verified = true group by name order by xp desc`;
    var lb2 =
      await sql`select name,(sum(coins)+(sum(kills)*100)) as xp from games where verified = true and EXTRACT(EPOCH FROM (now() - created_at)) < 86400 group by name order by xp desc`;
    res.render("user.ejs", {
      user: dbuser[0],
      games: yo,
      stats: stats,
      lb: lb,
      lb2: lb2,
    });
  }
});

Object.filter = (obj, predicate) =>
  Object.keys(obj)
    .filter((key) => predicate(obj[key]))
    .reduce((res, key) => ((res[key] = obj[key]), res), {});

/*************************************************************************************************/
/* Socket Connections ****************************************************************************/
/*************************************************************************************************/

// Create a new session of the game
var session = new Session({
  maxCoins: 2000,
  maxChests: 20,
  maxAiPlayers: 0,
  maxPlayers: 50
})

// When the socket connects
io.on("connection", async (socket) => {
  socket.joinTime = Date.now();
  socket.ip = socket.handshake.headers["x-forwarded-for"];

  // Check if the ip is banned
  if (moderation.bannedIps.includes(socket.ip)) {
    socket.emit(
      "ban",
      "You are banned. Appeal to gautamgxtv@gmail.com<br><br>BANNED IP: " +
        socket.ip
    );
    socket.disconnect();
  }

  // When the player wants to get into the game
  socket.on("go", async (r, captchatoken, tryverify, options) => {
    // When the sanity checks are passed, this function will run
    async function ready() {
      // Clean the name
      var name;
      if (!tryverify) {
        try {
          name = filter.clean(r.substring(0, 16));
        } catch (e) {
          name = r.substring(0, 16);
        }
      } else {
        var accounts = await sql`select * from accounts where secret=${r}`;
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

      // Create the player and get it ready
      var thePlayer = new Player(socket.id, name);
      thePlayer.updateValues();
      if (options && options.hasOwnProperty("movementMode")) {
        thePlayer.movementMode = options.movementMode;
      }
      if(tryverify) {
        thePlayer.verified = true;
        thePlayer.skin = accounts[0].skins.selected;
      }

      // Add the player to the session
      session.playerList.setPlayer(socket.id, thePlayer);
      console.log("player joined -> " + socket.id);

      // Emit the new player
      socket.broadcast.emit("new", thePlayer);

      // Emit the rest of the players
      var allPlayers = Object.values(PlayerList.players);
      allOtherPlayers = allPlayers.filter((player) => player.id != socket.id);
      if (allPlayers && allPlayers.length > 0) socket.emit("players", allPlayers);

      //TODO: Make coins emit only within range (not sure if this is done ill just leave this)
      // Emit the coins
      socket.emit("coins", coins.filter((coin) => coin.inRange(thePlayer)));

      // Emit the chests
      socket.emit("chests", chests);

      // Emit the levels
      socket.emit("levels", levels);

      // Set that the socket is joined
      socket.joined = true;
		}

    // Ban if captcha not sent
		if (!captchatoken && recaptcha) {
			socket.emit(
				"ban",
				"You were kicked for not sending a captchatoken. Send this message to gautamgxtv@gmail.com if you think this is a bug."
			);
			return socket.disconnect();
		}

    // Ban if not sent name
		if (!r) {
			socket.emit("ban", "You were kicked for not sending a name. ");
			return socket.disconnect();
		}

    // Ban if player is already connected
		if (PlayerList.has(socket.id)) {
			socket.emit(
				"ban",
				"You were kicked for 2 players on 1 id. Send this message to gautamgxtv@gmail.com<br> In the meantime, try restarting your computer if this happens a lot. "
			);
			return socket.disconnect();
		}
		
    // Ban if server is full
		if (Object.values(PlayerList.players).length >= maxPlayers) {
			socket.emit("ban", "Server is full. Please try again later.");
			return socket.disconnect();
		}

    // Do the captcha
		var send = {
			secret: process.env.CAPTCHASECRET,
			response: captchatoken,
			remoteip: socket.ip,
		};

		if(recaptcha) {
			axios
				.post(
					"https://www.google.com/recaptcha/api/siteverify?" +
          new URLSearchParams(send)
				)
				.then((f) => {
					f = f.data;

          // Ban if error during captcha
					if (!f.success) {
						socket.emit(
							"ban",
							"Error while verifying captcha<br>" + f["error-codes"].toString()
						);
						socket.disconnect();
						return;
					}

          // Ban if captcha failed
					if (f.score < 0.3) {
						socket.emit(
							"ban",
							`Captcha score too low: ${f.score}<br><br>If you're using a vpn, disable it. <br>If your on incognito, go onto a normal window<br>If your not signed in to a google account, sign in<br><br>If none of these worked, contact gautamgxtv@gmail.com`
						);
						socket.disconnect();
						return;
					}

          // See the defination of ready function above
					ready();
				});
		} else {
      // If no recaptcha, skip it
      ready();
    }
	});

  // When the player wants to evolve
  socket.on("evolve", (eclass) => {
    // If player is not in player list, return
    if(!PlayerList.has(socket.id)) return socket.emit("refresh");

    // Get the player
    var player = PlayerList.getPlayer(socket.id);

    // Some more sanity checks and then do the evolution
    if(player.evolutionQueue && player.evolutionQueue.length > 0 && player.evolutionQueue[0].includes(eclass.toLowerCase())) {
      eclass = eclass.toLowerCase();
      player.evolutionQueue.shift();
      var evo = evolutions[eclass]
      console.log(player.name + " evolved to " + eclass);
          
      player.evolutionData = {default: evo.default(), ability: evo.ability()};
      player.evolution =evo.name;
      player.skin = evo.name;
      player.updateValues();
      socket.emit("refresh");
      return;
    }
  });

  // When the player want to use an ability
  socket.on("ability", () => {
    // Get the player
    var player = PlayerList.getPlayer(socket.id);

    // If the player has an evolution
    if(player.evolution != "") {
      // check if ability activated already
      if(player.ability <= Date.now()) {
        // Activate ability
        player.ability = evolutions[player.evolution].abilityCooldown + evolutions[player.evolution].abilityDuration + Date.now();
        console.log(player.name + " activated ability");
        socket.emit("ability", [evolutions[player.evolution].abilityCooldown , evolutions[player.evolution].abilityDuration, Date.now()]);
      }
    }
  });

  // When the player has a new mousePos
	socket.on("mousePos", (mousePos) => {
		if (PlayerList.has(socket.id)) {
			var thePlayer = PlayerList.getPlayer(socket.id);
			thePlayer.mousePos = mousePos;
			PlayerList.updatePlayer(thePlayer);
     
		}
		else socket.emit("refresh");

		//console.log(mousePos.x +" , "+mousePos.y )
	});
  
  //  When the players mouse is down or up
	socket.on("mouseDown", (down) => {
		if (PlayerList.has(socket.id)) {
			var player = PlayerList.getPlayer(socket.id);
			if (player.mouseDown == down) return;
			[coins,chests] = player.down(down, coins, io, chests);
			PlayerList.updatePlayer(player);
		} else socket.emit("refresh");
	});

  // 
	socket.on("move", (controller) => {
		if (!controller) return;
		try {
			if (PlayerList.has(socket.id)) {
				var player = PlayerList.getPlayer(socket.id);
				player.move(controller);
				coins = player.collectCoins(coins, io, levels);
			}
		} catch (e) {
			console.log(e);
		}
	});
	socket.on( "ping", function ( fn ) {
		fn(); // Simply execute the callback on the client
	} );

  // When a player wants to chat
	socket.on("chat", (msg) => {
		msg = msg.trim().replace(/\\/g, "\\\\");
		if (msg.length > 0) {
      /// Trim the message
			if (msg.length > 35) msg = msg.substring(0, 35);

      // Sanity checks
			if (!PlayerList.has(socket.id) || Date.now() - PlayerList.getPlayer(socket.id).lastChat < 1000) return;

      // Set the last chat time
			var p = PlayerList.getPlayer(socket.id);
			p.lastChat = Date.now();
			// PlayerList.setPlayer(socket.id, p); I dont think this needs to be uncommented
			
      // Emit chat
      io.sockets.emit("chat", {
        msg: filter.clean(msg),
        id: socket.id,
      });
		}
	});

  // Def should put this in util
	function clamp(num, min, max) {
		return num <= min ? min : num >= max ? max : num;
	}

  // When the player wants to leave
	socket.on("disconnect", () => {
    // If the server is shutting down ignore this
		if(serverState == "exiting") return;

    // Sanity checks
		if (!PlayerList.has(socket.id)) return;

    // Get the player
		var thePlayer = PlayerList.getPlayer(socket.id);

    //drop their coins randomly near them
    var drop = [];
    var dropAmount = clamp(Math.round(thePlayer.coins*0.8), 10, 20000);
    var dropped = 0;
    while (dropped < dropAmount) {
      var r = thePlayer.radius * thePlayer.scale * Math.sqrt(Math.random());
      var theta = Math.random() * 2 * Math.PI;
      var x = thePlayer.pos.x + r * Math.cos(theta);
      var y = thePlayer.pos.y + r * Math.sin(theta);
      var remaining = dropAmount - dropped;
      var value = remaining > 50 ? 50 : (remaining > 10 ? 10 : (remaining > 5 ? 5 : 1));

      coins.push(
        new Coin({
          x: clamp(x, -(map/2), map/2),
          y: clamp(y, -(map/2), map/2),
        }, value)
      );

      dropped += value;
      drop.push(coins[coins.length - 1]);
    }

    // Emit the new coins
    io.sockets.emit("coin", drop, [thePlayer.pos.x, thePlayer.pos.y]);    

//		sql`INSERT INTO games (name, coins, kills, time, verified) VALUES (${thePlayer.name}, ${thePlayer.coins}, ${thePlayer.kills}, ${Date.now() - thePlayer.joinTime}, ${thePlayer.verified})`;

    // Delete the player
		PlayerList.deletePlayer(socket.id);

    // Emit the player left
		socket.broadcast.emit("playerLeave", socket.id);
	});
});


/***********************************************/
/* Tick ****************************************/
/***********************************************/

// The last second that was surpassed, used for computing tps
var secondStart = Date.now();

// The last time that the server sent out a PSA about where all the chests and coins are
// For some reason the server does this every 10 seconds
var lastChestSend = Date.now();
var lastCoinSend = Date.now();

// The counter for ticks per second
// increamented every time a tick runs
var tps = 0;

// The actual ticks per second, hold the last tps value that was valid
// (This is used because the tps variable is used for calculating the ticks per second)
var actps = 0;

// app/api/serverinfo leads to a json of stats
app.get("/api/serverinfo", (req, res) => {
  var playerCount = Object.values(PlayerList.players).length;
  var lag = actps > 15 ? "No lag" : actps > 6 ? "Moderate lag" : "Extreme lag";
  res.send({
    playerCount,
    lag,
    maxPlayers,
    tps: actps,
    actualPlayercount: Object.values(PlayerList.players).filter((p) => !p.ai)
      .length,
  });
});

// 30 times per second do this (1000 / 30 ms)
setInterval(async () => {
	//const used = process.memoryUsage().heapUsed / 1024 / 1024;
//console.log(`The script uses approximately ${Math.round(used * 100) / 100} MB`);

  // clean up the playerlist
	PlayerList.clean();

  // Set the mod io to io???? (idk why this is here)
	moderation.io = io;

  // Add a new coin if the maxCoins are not reached
	if (coins.length < maxCoins) {
		coins.push(new Coin());
		io.sockets.emit("coin", coins[coins.length - 1]);
	}

  // Add a new chest if the maxChests are not reached
	if(chests.length < maxChests) {
		chests.push(new Chest());
		io.sockets.emit("chest", chests[chests.length - 1]);
	}

  // TODO: just create methods from these, much more readable
	var normalPlayers = Object.values(PlayerList.players).filter(p => p && !p.ai).length;
	var aiPlayers = Object.keys(PlayerList.players).length;

  // Add a new ai player if there are real players and a random condition is met
	if (normalPlayers > 0 && aiPlayers < maxAiPlayers && getRandomInt(0,100) == 5) {
    // Create the ai player
		var id = uuidv4();
		var theAi = new AiPlayer(id);
		console.log("AI Player Joined -> "+theAi.name);

    // Add it to the list
		PlayerList.setPlayer(id, theAi);

    // Emit a new player
		io.sockets.emit("new", theAi);
	}

	// If its been one second since lst calculating the tps
	if (Date.now() - secondStart >= 1000) {
    // Emit ticks per second
		io.sockets.emit("tps", tps);

    // Update the actual ticks per second varaible
		actps = tps;
		//console.log("Players: "+Object.keys(players).length+"\nTPS: "+tps+"\n")

    // Update when the tps was last calculated
		secondStart = Date.now();

    // Restart the tps counter
		tps = 0;
	}

  // If its been 10 seconds since the last chest PSA
	if (Date.now() - lastChestSend >= 10000) {
    // Emit the chests
		io.sockets.emit("chests", chests);

    // Update the last time it happened
		lastChestSend = Date.now();
	}

  // Get all the sockets
	var sockets = await io.fetchSockets();

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
  var playersarray = Object.values(PlayerList.players);
	playersarray.forEach((player) => {
		if (player) {
      // Update the player values
      player.updateValues()
			//   player.moveWithMouse(players)

      // Tick ai players
			if(player.ai) {
				[coins, chests] = player.tick(coins, io, levels, chests);
			}

      // if its been x seconds since player got hit, regen then every 100 ms
			if (
				Date.now() - player.lastHit > player.healWait &&
        Date.now() - player.lastRegen > 75 &&
        player.health < player.maxHealth
			) {
				// Heal ❤️
				player.lastRegen = Date.now();
				player.health += (player.health / 100)*player.healAmount;
			}

      // Might be unessicary
      // Not sure
      // But this updates the player in the playerList
			PlayerList.updatePlayer(player);

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
          if(Date.now() - lastCoinSend >= 1000) {
            // Emit the coins the are next to the player
            socket.emit("coins", coins.filter((coin) => coin.inRange(player)));
          }
				}
			});
		}
	});

  // reset the time when the last coin send was
	if(Date.now() - lastCoinSend >= 1000) {
		lastCoinSend = Date.now();
	}

  // Increment tps for calculation
	tps += 1;
}, 1000 / 30);

// Start the server and listen on the port in the .env
// If the port is not in the .env, then use 3000
server.listen(process.env.PORT || 3000, () => {
  console.log("server started");
});

// When the code is told to stop
process.on("SIGTERM", () => {
  // Do a clean exit
  cleanExit()
    .then(() => {
      console.log("exited cleanly");
      process.exit(1);
    })
    .catch(() => {
      console.log("failed to exit cleanly");
      process.exit(1);
    });
});

// When ctrl-C is pressed in terminal
process.on("SIGINT", () => {
  // Do a clean exit
  cleanExit()
    .then(() => {
      console.log("exited cleanly");
      process.exit(1);
    })
    .catch(() => {
      console.log("failed to exit cleanly");
      process.exit(1);
    });
});

// When there is a an unhandled rejection
process.on("unhandledRejection", (reason, p) => {
  console.log("Unhandled Rejection at: Promise", p, "reason:", reason);
  cleanExit()
    .then(() => {
      console.log("exited cleanly");
      process.exit(1);
    })
    .catch(() => {
      console.log("failed to exit cleanly");
      process.exit(1);
    });
});

// Cleanly exit
async function cleanExit() {
  console.log("exiting cleanly...");

  // Set the server state to exiting
  // This will make it so players leaving are ignored
  serverState = "exiting";

  // Get all the sockets
  var sockets = await io.fetchSockets();

  // For each player
  for (var player of Object.values(PlayerList.players)) {
    // If the player is a real player
    if (player && !player.ai) {

      // Get the socket that corresponds with the player
      var socket = sockets.find((s) => s.id == player.id);

      // If there is a socket that corresponds
      if (socket) {
        // Ban the player or being in the server when it was closing ;(
        socket.emit(
          "ban",
          "<h1>Server is shutting down, we'll be right back!<br>Sorry for the inconvenience.<br><br>" +
            (player.verified
              ? " Your Progress has been saved in your account"
              : "") +
            "</h1><hr>"
        );
        socket.disconnect();

        // Save the player stats
        await sql`INSERT INTO games (name, coins, kills, time, verified) VALUES (${
          player.name
        }, ${player.coins}, ${player.kills}, ${Date.now() - player.joinTime}, ${
          player.verified
        })`;
      }
    }
  }
}

/*
http.createServer(function (req, res) {
    res.writeHead(301, { "Location": "https://" + req.headers["host"] + req.url });
    res.end();
}).listen(80);
*/
