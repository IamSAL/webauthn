import base64url from "./base64url-arraybuffer";

function publicKeyCredentialToJSON(pubKeyCred) {
  if (pubKeyCred instanceof Array) {
    let arr = [];
    for (let i of pubKeyCred) arr.push(publicKeyCredentialToJSON(i));

    return arr;
  } else if (pubKeyCred instanceof ArrayBuffer) {
    return base64url.encode(pubKeyCred);
  } else if (pubKeyCred instanceof Object) {
    let obj = {};

    for (let key in pubKeyCred) {
      obj[key] = publicKeyCredentialToJSON(pubKeyCred[key]);
    }

    return obj;
  }

  return pubKeyCred;
}

function generateRandomBuffer(len) {
  len = len || 32;

  const randomBuffer = new Uint8Array(len);
  window.crypto.getRandomValues(randomBuffer);

  return randomBuffer;
}

let preformatMakeCredReq = (makeCredReq) => {
  let modieifiedCred = { ...makeCredReq };
  modieifiedCred.challenge = base64url.decode(modieifiedCred.challenge);
  modieifiedCred.user.id = base64url.decode(modieifiedCred.user.id);

  return modieifiedCred;
};

let preformatGetAssertReq = (getAssert) => {
  getAssert.challenge = base64url.decode(getAssert.challenge);

  for (let allowCred of getAssert.allowCredentials) {
    allowCred.id = base64url.decode(allowCred.id);
  }

  return getAssert;
};

function isPlatformWebAuthnSupport() {
  return new Promise((resolve, reject) => {
    if (
      window.location.protocol === "http:" &&
      window.location.hostname !== "localhost" &&
      window.location.hostname !== "127.0.0.1"
    ) {
      resolve(false);
    }
    if (
      window.PublicKeyCredential === undefined ||
      typeof window.PublicKeyCredential !== "function"
    ) {
      resolve(false);
    }

    window.PublicKeyCredential.isUserVerifyingPlatformAuthenticatorAvailable().then(
      (supported) => {
        if (supported) {
          resolve(true);
        } else {
          resolve(false);
        }
      }
    );
  });
}

export {
  publicKeyCredentialToJSON,
  generateRandomBuffer,
  preformatGetAssertReq,
  preformatMakeCredReq,
  isPlatformWebAuthnSupport,
};
