import crypto from "crypto";
import base64url from "base64url";

export const randomBase64URLBuffer = (len) => {
    len = len || 32;
    let buff = crypto.randomBytes(len);
    return base64url(buff);
};

