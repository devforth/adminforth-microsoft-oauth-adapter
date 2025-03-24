import type { OAuth2Adapter } from "adminforth";
import { jwtDecode } from "jwt-decode";

export default class AdminForthAdapterMicrosoftOauth2 implements OAuth2Adapter {
    private clientID: string;
    private clientSecret: string;
    private useOpenID: boolean;

    constructor(options: {
      clientID: string;
      clientSecret: string;
      useOpenID?: boolean;
    }) {
      this.clientID = options.clientID;
      this.clientSecret = options.clientSecret;
      this.useOpenID = options.useOpenID ?? true;
    }
  
    getAuthUrl(): string {
      const params = new URLSearchParams({
        client_id: this.clientID,
        response_type: 'code',
        scope: 'openid email profile https://graph.microsoft.com/user.read',
        response_mode: 'query',
        redirect_uri: 'http://localhost:3000/oauth/callback',
      });
      return `https://login.microsoftonline.com/common/oauth2/v2.0/authorize?${params.toString()}`;
    }
  
    async getTokenFromCode(code: string, redirect_uri: string): Promise<{ email: string; }> {
      const tokenResponse = await fetch('https://login.microsoftonline.com/common/oauth2/v2.0/token', {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({
          code,
          client_id: this.clientID,
          client_secret: this.clientSecret,
          redirect_uri,
          grant_type: 'authorization_code',
        }),
      });
  
      const tokenData = await tokenResponse.json();
      
      if (tokenData.error) {
        console.error('Token error:', tokenData);
        throw new Error(tokenData.error_description || tokenData.error);
      }

      if (this.useOpenID && tokenData.id_token) {
        try {
          const decodedToken: any = jwtDecode(tokenData.id_token);
          if (decodedToken.email) {
            return { email: decodedToken.email };
          }
        } catch (error) {
          console.error("Error decoding token:", error);
        }
      }
  
      const userResponse = await fetch('https://graph.microsoft.com/v1.0/me', {
        headers: { Authorization: `Bearer ${tokenData.access_token}` },
      });
      
      const userData = await userResponse.json();
  
      if (userData.error) {
        throw new Error(userData.error.message || 'Failed to fetch user data');
      }
  
      return {
        email: userData.mail || userData.userPrincipalName,
      };
    }

    getIcon(): string {
      return `<?xml version="1.0" encoding="utf-8"?>
<svg viewBox="0 0 24 24" xmlns="http://www.w3.org/2000/svg" fill="none"><rect width="24" height="24" fill="#F25022"/><path d="M11 2H2V11H11V2Z" fill="#F25022"/><path d="M22 2H13V11H22V2Z" fill="#7FBA00"/><path d="M11 13H2V22H11V13Z" fill="#00A4EF"/><path d="M22 13H13V22H22V13Z" fill="#FFB900"/></svg>`;
    }
}
