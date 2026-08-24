// Prepend the standard Ed25519 ASN.1 SPKI header so Web Crypto can parse raw keys
function hexToSpki(hexKey) {
	const spkiHeader = new Uint8Array([
		0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
	]);
	const rawKeyBytes = new Uint8Array(hexKey.match(/.{1,2}/g).map(b => parseInt(b, 16)));
	const spki = new Uint8Array(spkiHeader.length + rawKeyBytes.length);
	spki.set(spkiHeader);
	spki.set(rawKeyBytes, spkiHeader.length);
	return spki;
}

function hexToBytes(hex) {
	return new Uint8Array(hex.match(/.{1,2}/g).map(b => parseInt(b, 16)));
}

async function verifyDiscordRequest(request, publicKeyHex) {
	const signature = request.headers.get('X-Signature-Ed25519');
	const timestamp = request.headers.get('X-Signature-Timestamp');
	if (!signature || !timestamp || !publicKeyHex) {
		return {
			isValid: false,
			body: ''
		};
	}
	const body = await request.text();
	try {
		const key = await crypto.subtle.importKey('spki', hexToSpki(publicKeyHex.trim()), {
				name: 'Ed25519'
			}, false,
			['verify']);
		const data = new TextEncoder().encode(timestamp + body);
		const signatureBytes = hexToBytes(signature);
		const isValid = await crypto.subtle.verify('Ed25519', key, signatureBytes, data);
		return {
			isValid,
			body
		};
	} catch (err) {
		return {
			isValid: false,
			body
		};
	}
}

function dedent(str) {
	const lines = str.split('\n');
	const indent = lines[1].match(/^\s*/)[0].length;
	return lines.map(line => line.slice(indent)).join('\n').trim();
}

// Check is this Me
function isThisRay(interaction) {
	const Ray = 1375628471358849054;
	if (interaction.member.user.id === Ray) {
		return true;
	}
	return false;
}

// ban word check
async function updateOrGetBanWord(env, action, string, flag) {
  // Fetch current JSON list
  const row = await env.DB.prepare(
    "SELECT content FROM ban_word LIMIT 1"
  ).first();

  let list = [];

  if (row?.content) {
    try {
      list = JSON.parse(row.content);
      if (!Array.isArray(list)) list = [];
    } catch {
      list = [];
    }
  }

  // Helper: decode ASCII if needed
  let decoded = string;
  if (flag === 2) {
    try {
      decoded = string
        .split(" ")
        .map(n => String.fromCharCode(parseInt(n)))
        .join("");
    } catch {
      return {
        action,
        code: 1,
        list,
        string,
        decoded: null
      };
    }
  }

  // ACTION 1: return list only
  if (action === 1) {
    return {
      action: 1,
      code: 0,
      list,
      string,
      decoded
    };
  }

  // ACTION 2: add word
  if (action === 2) {
    list.push(decoded);

    await env.DB.prepare(
      "UPDATE ban_word SET content = ?"
    ).bind(JSON.stringify(list)).run();

    return {
      action: 2,
      code: 0,
      list,
      string,
      decoded
    };
  }

  // ACTION 3: delete word
  if (action === 3) {
    const index = list.indexOf(decoded);

    if (index === -1) {
      return {
        action: 3,
        code: 1,
        list,
        string,
        decoded
      };
    }

    list.splice(index, 1);

    await env.DB.prepare(
      "UPDATE ban_word SET content = ?"
    ).bind(JSON.stringify(list)).run();

    return {
      action: 3,
      code: 0,
      list,
      string,
      decoded
    };
  }

  return {
    action: "error",
    code: 1,
    list,
    string,
    decoded
  };
}

async function getOrCreateUser(env, userID) {
  // Try to read the user
  const user = await env.DB.prepare(
    "SELECT violationCount, availableUntil FROM users WHERE userID = ?"
  ).bind(userID).first();

  if (user) {
    // User exists → return the two numbers
    return {
      exists: true,
      violationCount: user.violationCount,
      availableUntil: user.availableUntil
    };
  }

  // User does not exist → create with defaults
  await env.DB.prepare(
    "INSERT INTO users (userID, violationCount, availableUntil) VALUES (?, 0, -1)"
  ).bind(userID).run();

  return {
    exists: false,
    violationCount: 0,
    availableUntil: -1
  };
}

async function updateUser(env, userID, code, value) {
  // Fetch existing user
  let user = await env.DB.prepare(
    "SELECT violationCount, availableUntil FROM users WHERE userID = ?"
  ).bind(userID).first();

  // If user doesn't exist, create with defaults
  if (!user) {
    await env.DB.prepare(
      "INSERT INTO users (userID, violationCount, availableUntil) VALUES (?, 0, -1)"
    ).bind(userID).run();

    user = { violationCount: 0, availableUntil: -1 };
  }

  // Update based on code
  if (code === 1) {
    user.violationCount = value;

    await env.DB.prepare(
      "UPDATE users SET violationCount = ? WHERE userID = ?"
    ).bind(value, userID).run();
  }

  if (code === 2) {
    user.availableUntil = value;

    await env.DB.prepare(
      "UPDATE users SET availableUntil = ? WHERE userID = ?"
    ).bind(value, userID).run();
  }

  // Return updated user
  return {
    userID,
    violationCount: user.violationCount,
    availableUntil: user.availableUntil
  };
}



// Request Handler System.
function handleRequest(interaction) {
	// PING (Discord verification)
	if (interaction.type === 1) {
		return {
			type: 1
		};
	}

	// command: /say
	if (interaction.type === 2 && interaction.data.name === 'say') {
		const message = interaction.data.options?.find(o => o.name === 'message')?.value || '';
		const userId = interaction.data.options?.find(o => o.name === 'user')?.value;
		const blacklist = ["67", "gay", "six seven", "6️⃣", "7️⃣", "sixseven", "sixty seven", "six seven", "ass", "6.7", "6,7", "6 7", "6  7", "sybau"];
		if (blacklist.some(word => message.includes(word))) {
			const content = `### **Matthew 22:37**
Matthew 22:37 records Jesus’s reply:  
**“Love the Lord your God with all your heart and with all your soul and with all your mind.”**

---

### **Context and Meaning**

#### **The Greatest Commandment**
A religious expert asks Jesus which command in the law is the most important, and Jesus responds with this verse.

#### **Total Devotion**
Jesus quotes from Deuteronomy to show that God desires our whole life—our deepest feelings, our inner self, and our honest thoughts.

#### **The Second Rule**
Right after this, in verse 39, Jesus adds:  
**“Love your neighbor as yourself.”**  
He explains that all of God’s teachings depend on these two core principles.
`;
			return {
				type: 4,
				data: {
					content
				}
			};
		}
		const content = userId ? `<@${userId}> ${message}` : message;
		return {
			type: 4,
			data: {
				content
			}
		};
	}

	if (interaction.type === 2 && interaction.data.name === 'shortout') {
		const message = interaction.data.options?.find(o => o.name === 'message')?.value || '';
		const userId = interaction.data.options?.find(o => o.name === 'user')?.value;
		const blacklist = ["67", "gay", "six seven", "6️⃣", "7️⃣", "sixseven", "sixty seven", "six seven", "ass", "6.7", "6,7", "6 7", "6  7", "sybau"];
		if (blacklist.some(word => message.includes(word))) {
			const content = `# **Matthew 22:37**
## Matthew 22:37 records Jesus’s reply:  
## **“Love the Lord your God with all your heart and with all your soul and with all your mind.”**

---

# **Context and Meaning**

## The Greatest Commandment
### A religious expert asks Jesus which command in the law is the most important, and Jesus responds with this verse.

## Total Devotion
### Jesus quotes from Deuteronomy to show that God desires our whole life—our deepest feelings, our inner self, and our honest thoughts.

## The Second Rule
### Right after this, in verse 39, Jesus adds:  
### **“Love your neighbor as yourself.”**  
### He explains that all of God’s teachings depend on these two core principles.
`;
			return {
				type: 4,
				data: {
					content
				}
			};
		}
		const content = userId ? `# <@${userId}> ${message}` : `# ${message}`;
		return {
			type: 4,
			data: {
				content
			}
		};
	}

	// command: /showme
	if (interaction.type === 2 && interaction.data.name === 'showme') {
		const getOrMissing = (value) => value ?? 'Not found (you maybe in DM)';

		const username = getOrMissing(interaction.member?.user?.username);
		const userId = getOrMissing(interaction.member?.user?.id);
		const joinedAt = getOrMissing(interaction.member?.joined_at);
		const guildId = getOrMissing(interaction.guild_id);
		const channelId = getOrMissing(interaction.channel_id);

		const initContent = `
			# Hello <@${userId}> !

			**Here is your stats on Discord:**
			Username: \`${username}\`
			Member ID: \`${userId}\`

			**Also, useful information for what you see here:**
			Discord Server ID: \`${guildId}\`
			Channel ID: \`${channelId}\`
			Click here to check if you are in correct place: https://discord.com/channels/${guildId}/${channelId}

			**Thank you for using Agent for Ray! Hope you enjoy the Agent!**

			> This is Agent for Ray. If you like me, install me to your app or your server!
		`;

		const content = dedent(initContent);
		return {
			type: 4,
			data: { content }
		};
	}

	// command: /avatar
	if (interaction.type === 2 && interaction.data.name === 'avatar') {
		// Works for both guild interactions (member.user) and DM interactions (user)
		const user = interaction.member?.user || interaction.user;
		if (!user) {const content = null};

		const userId = user.id;
		const avatarHash = user.avatar;

		// If the user has no custom avatar, use the default avatar
		if (!avatarHash) {
			const defaultIndex = Number(userId) % 5; // Discord has 5 default avatars
			const content = `https://cdn.discordapp.com/embed/avatars/${defaultIndex}.png?size=512`;
		}

		// Detect GIF vs PNG
		const isGif = avatarHash.startsWith("a_");
		const extension = isGif ? "gif" : "png";

		const content = `https://cdn.discordapp.com/avatars/${userId}/${avatarHash}.${extension}?size=512`;

		return {
			type: 4,
			data: { content }
		};
	}	

	// command: 3 dots > Repeat
	if (interaction.type === 3) {
		const targetId = interaction.data.target_id;
		const targetMessage = interaction.data.resolved?.messages?.[targetId];
		const content = targetMessage?.content || "Could not retrieve message content.";
		return {
			type: 4,
			data: {
				content
			}
		};
	}

	return {
		type: 4,
		data: "Sorry, this command is invalid"
	};



	// ADMIN COMMAND!

	// command: /banword

}




function shouldDefer(interaction) {
  // Fast commands: respond immediately
  const fastCommands = ["say", "tos"];

  if (interaction.type === 2) {
    return !fastCommands.includes(interaction.data.name);
  }

  // Message context menu (Repeat) is fast
  if (interaction.type === 3) {
    return true;
  }

  return false;
}

async function handleDeferred(interaction, env) {
  const result = handleRequest(interaction);

  // Extract the content safely
  const content = result?.data?.content;

  if (!content) {
    // fallback
    await fetch(
      `https://discord.com/api/v10/webhooks/${interaction.application_id}/${interaction.token}`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ content: "No content returned." })
      }
    );
    return;
  }

  // Correct follow-up format
  await fetch(
    `https://discord.com/api/v10/webhooks/${interaction.application_id}/${interaction.token}`,
    {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ content })
    }
  );
}



export default {
  async fetch(request, env, ctx) {
    if (request.method !== "POST") {
      return new Response("Method Not Allowed", { status: 405 });
    }

    const { isValid, body } = await verifyDiscordRequest(request, env.PUBLIC_KEY);
    if (!isValid) {
      return new Response("Invalid signature", { status: 401 });
    }

    const interaction = JSON.parse(body);

    // PING
    if (interaction.type === 1) {
      return Response.json({ type: 1 });
    }

    const defer = shouldDefer(interaction);

    if (defer) {
      // Respond immediately
      const response = Response.json({ type: 5 });

      // Background work
      ctx.waitUntil(handleDeferred(interaction, env));

      return response;
    }

    // Immediate response
    const result = handleRequest(interaction);
    return Response.json(result);
  }
};
