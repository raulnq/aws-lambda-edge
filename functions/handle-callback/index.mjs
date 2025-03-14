const TENANT_ID = '<MY_TENANT_ID>';
const CLIENT_ID =  '<MY_CLIENT_ID>';

export const Handler = async (event, context) => {

    const request = event.Records[0].cf.request;

    console.info(request);

    const queryParams = request.querystring ? Object.fromEntries(new URLSearchParams(request.querystring)) : {};

    const cookies = parseCookies(request.headers.cookie || []);

    if(queryParams.code && cookies.code_verifier)
    {
      const tokens = await exchangeCode(queryParams.code, cookies.code_verifier, request.headers.host[0].value);
      if(tokens){
        return redirectToRoot(tokens);
      }
    }

    return returnError();
  };

function returnError()
{
  return {
    status: '400',
    statusDescription: 'Bad Request',
    headers: {
      'content-type': [{
        key: 'Content-Type',
        value: 'text/html'
      }]
    },
    body: '<html><body><h1>Error</h1><p>Authentication error</p></body></html>'
  };
}

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

async function exchangeCode(code, codeVerifier, domainName) {
  console.info("Exchanging code...");
  const url = `https://login.microsoftonline.com/${TENANT_ID}/oauth2/v2.0/token`;
  const body = new URLSearchParams({
    client_id: CLIENT_ID,
    grant_type: 'authorization_code',
    code: code,
    redirect_uri: `https://${domainName}/callback`,
    code_verifier: codeVerifier
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
    console.error('Exchange code error:', response.status);
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