require("dotenv").config();
const crypto = require("crypto");
const axios = require("axios");

const generateCnonce = (length) =>
    Array.from({ length }, () => Math.random().toString(36)[2] || "0").join("");

const username = process.env.PUBLIC_KEY;
const password = process.env.PRIVATE_KEY;
const uri = "https://cloud.mongodb.com/api/atlas/v2/orgs";
const nc = "00000001";
const cnonce = generateCnonce(8);
async function digestAuthRequest() {
    let realm, nonce, qop, opaque;
    // Initial request to get the WWW-Authenticate header
    try {
        await axios.get(uri, {
            headers: { Accept: "application/vnd.atlas.2023-01-01+json" },
        });
    } catch (error) {
        if (error.response.status === 401) {
            const wwwAuthenticateHeader =
                error.response.headers["www-authenticate"];
            console.log(wwwAuthenticateHeader);
            const headerValues = wwwAuthenticateHeader.split(", ");
            console.log(JSON.stringify({ headerValues }, null, 2));
            // Extract values from WWW-Authenticate header
            headerValues.forEach((value) => {
                if (value.startsWith("Digest realm")) {
                    realm = value.split("=")[1].replace(/"/g, "");
                } else if (value.startsWith("nonce")) {
                    nonce = value.split("=")[1].replace(/"/g, "");
                } else if (value.startsWith("qop")) {
                    qop = value.split("=")[1].replace(/"/g, "");
                } else if (value.startsWith("opaque")) {
                    opaque = value.split("=")[1].replace(/"/g, "");
                }
            });
            console.log(
                JSON.stringify(
                    {
                        realm,
                        nonce,
                        qop,
                        opaque,
                    },
                    null,
                    2
                )
            );
        } else {
            console.error(error);
            return;
        }
    }

    // Create hashes
    const ha1 = crypto
        .createHash("md5")
        .update(`${username}:${realm}:${password}`)
        .digest("hex");

    const ha2 = crypto.createHash("md5").update(`GET:${uri}`).digest("hex");
    const response = crypto
        .createHash("md5")
        .update(`${ha1}:${nonce}:${nc}:${cnonce}:${qop}:${ha2}`)
        .digest("hex");

    console.log(JSON.stringify({ ha1, ha2, response }, null, 2));

    // Send request with Digest auth
    try {
        const result = await axios.get(uri, {
            headers: {
                Authorization: `Digest username="${username}", realm="${realm}", nonce="${nonce}", uri="${uri}", qop=${qop}, nc=${nc}, cnonce="${cnonce}", response="${response}", opaque="${opaque}"`,
                Accept: "application/vnd.atlas.2023-01-01+json",
            },
        });
        console.log(result.data);
    } catch (error) {
        // console.error(error);
    }
}

digestAuthRequest();
