import crypto from 'crypto';
import jwt  from 'jsonwebtoken';
import jwksClient  from 'jwks-rsa';

const TENANT_ID = '77f43f1b-5708-46dd-92a2-5f99f19e9b1f';
const CLIENT_ID =  '795eb294-1fb1-4454-9fa0-5563a03880ac';


export const Handler = async (event, context) => {

    const request = event.Records[0].cf.request;

    console.info(request);

    const cookies = parseCookies(request.headers.cookie || []);

    if(cookies.access_token && cookies.refresh_token){
      try {
        const verifiedToken = verifyToken(cookies.access_token);
        if(verifiedToken)
        {
          return request;
        }
      } catch (error) {
        console.error('Verify token error:', error.name, error.message);
        if (error.name=='TokenExpiredError') {
          const newtokens = await exchangeRefreshToken(cookies.refresh_token, request.headers.host[0].value);
          if(newtokens){
            redirectToRoot(newtokens);
          }
        }
      }
    } 

    return redirectToAzure(request.headers.host[0].value);
  };

function redirectToRoot(tokens)
{
  return { 
    status: '302', 
    headers: { 
      location: [
        { key: 'Location', value: '/' }
      ],
      'set-cookie': [
        { key: 'Set-Cookie', value: `access_token=${tokens.access_token}; Path=/; Secure; HttpOnly` },
        { key: 'Set-Cookie', value: `refresh_token=${tokens.refresh_token}; Path=/; Secure; HttpOnly` }
      ] 
    } 
  };
}

function redirectToAzure(domainName){
  console.info("Redirecting to Azure...");
  const codeVerifier = crypto.randomBytes(32).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  const codeChallenge = crypto.createHash('sha256').update(codeVerifier).digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
  const state = crypto.randomBytes(16).toString('hex');
  const authUrl = `https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/authorize?` +
      `client_id=${CLIENT_ID}` +
      `&response_type=code` +
      `&redirect_uri=${encodeURIComponent(`https://${domainName}/callback`)}` +
      `&scope=${encodeURIComponent(`openid profile email api://${CLIENT_ID}/download`)}` +
      `&code_challenge=${encodeURIComponent(codeChallenge)}` +
      `&code_challenge_method=S256` +
      `&state=${encodeURIComponent(state)}` +
      `&response_mode=query`;
  const response = {
        status: '302',
        statusDescription: 'Found',
        headers: {
            location: [{
                key: 'Location',
                value: authUrl
            }],
            'set-cookie': [{
                key: 'Set-Cookie',
                value: `code_verifier=${codeVerifier}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600`
            }]
        }
    };
  return response;
}

async function verifyToken(access_token){
  console.info("Verifying token...");
  const client = jwksClient({jwksUri: `https://login.microsoftonline.com/${TENANT_ID}/discovery/v2.0/keys`});
  const decoded = jwt.decode(access_token, { complete: true });
  if(!decoded){
    console.error('Decode token error');
    return null;
  }
  const key = await client.getSigningKey(decoded.header.kid);
  return jwt.verify(access_token, key.getPublicKey(), {
    audience: `api://${CLIENT_ID}`,
    issuer: `https://sts.windows.net/${TENANT_ID}/`,
    algorithms: ["RS256"]
  });
}

async function exchangeRefreshToken(refresh_token, domainName) {
  console.info("Refreshing token...");
  const url = `https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token`;
  const body = new URLSearchParams({
    client_id: CLIENT_ID,
    grant_type: 'refresh_token',
    refresh_token: refresh_token
  });
  const response = await fetch(url, {
    method: 'POST',
    headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Origin': `https://${domainName}`
    },
    body: body
  });
  if (!response.ok) {
    console.error('Exchange refresh token error:', response.status);
    return null;
  }
  return await response.json();
}

function parseCookies(cookieHeaders) {
  const cookies = {};
  
  if (!cookieHeaders || !cookieHeaders.length) {
      return cookies;
  }
  

  cookieHeaders.forEach(header => {
      if (header.value) {
          header.value.split(';').forEach(cookie => {
              const parts = cookie.trim().split('=');
              if (parts.length >= 2) {
                  cookies[parts[0].trim()] = parts.slice(1).join('=');
              }
          });
      }
  });
  
  return cookies;
}
