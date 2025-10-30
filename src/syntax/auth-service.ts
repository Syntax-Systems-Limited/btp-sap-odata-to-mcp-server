/**
 * SYNTAX - Custom override of auth-service.ts to authenticate clients via API Key (Bearer token)
 * instead of using XSUAA.
 * 
 * XSUAA will not be used at all for authentication.
 * The API Key must be configured in the environment variable MCP_API_KEY (either in .env or User-provided variables)
 */

import xssec, { createSecurityContext } from '@sap/xssec';
import xsenv from '@sap/xsenv';
import { Request, Response, NextFunction } from 'express';
import { Logger } from '../utils/logger.js';
import { Config } from '../utils/config.js';
import { DummySecurityContext } from './DummySecurityContext.js';

export interface AuthRequest extends Request {
    authInfo?: xssec.SecurityContext;
    jwtToken?: string;
}

export class AuthService {
    private logger: Logger;
    private config: Config;
    private apiKey: string|undefined;

    constructor(logger?: Logger, config?: Config) {
        this.logger = logger || new Logger('AuthService');
        this.config = config || new Config();

        this.apiKey = process.env.MCP_API_KEY;
        if (!this.apiKey) {
            throw new Error('API key is not configured (environment variable MCP_API_KEY)');
        }
    }

    getAuthorizationUrl(state?: string, requestUrl?: string): string {
        return 'n/a';
    }

    async exchangeCodeForToken(code: string, redirectUri?: string): Promise<{ access_token: string; refresh_token?: string; expires_in: number }> {
        return {
            access_token: 'dummy',
            refresh_token: 'dummy',
            expires_in: 99999
        };
    }

    async refreshAccessToken(refreshToken: string): Promise<{ accessToken: string; refreshToken?: string; expiresIn: number }> {
        return {
            accessToken: 'dummy',
            refreshToken: 'dummy',
            expiresIn: 99999
        };
    }

    /**
     * SYNTAX custom implementation - Validate API Key
     */
    authenticateJWT() {
        return async (req: AuthRequest, res: Response, next: NextFunction) => {
            // Skip authentication for health and docs endpoints
            if (req.path === '/health' || req.path === '/docs' || req.path === '/oauth/authorize' || req.path === '/oauth/callback') {
                return next();
            }

            const authHeader = req.headers.authorization;
            if (!authHeader || !authHeader.startsWith('Bearer ')) {
                return res.status(401).json({
                    error: 'Authentication Required',
                    message: 'API Key required',
                    authentication: {
                        required: true,
                        type: 'Bearer Token'
                    }
                });
            }

            const token = authHeader.substring(7);
            if (token == this.apiKey) {
                req.authInfo = new DummySecurityContext();
                return next();
            }
            else {
                this.logger.error('Authentication failed: invalid API Key');
                return res.status(401).json({
                    error: 'Invalid API Key',
                    message: 'The provided API Key is invalid',
                    authentication: {
                        required: true,
                        type: 'Bearer Token'
                    }
                });
            }
        };
    }

    optionalAuthenticateJWT() {
        return async (req: AuthRequest, res: Response, next: NextFunction) => {
            req.authInfo = new DummySecurityContext();
            return next();
        };
    }

    hasScope(securityContext: xssec.SecurityContext, scope: string): boolean {
        return true;
    }

    getRedirectUri(requestUrl?: string): string {
        return 'n/a';
    }

    isConfigured(): boolean {
        return true;
    }

    getXSUAADiscoveryMetadata() {
        return {
            issuer: 'dummy',
            clientId: 'dummy',
            xsappname: 'dummy',
            identityZone: 'dummy',
            tenantId: 'dummy',
            tenantMode: 'dummy',
            endpoints: {
                authorization: 'dummy',
                token: 'dummy',
                userinfo: 'dummy',
                jwks: 'dummy',
                introspection: 'dummy',
                revocation: 'dummy'
            },
            verificationKey: 'dummy'
        };
    }

    getApplicationScopes(): string[] {
        const appName = 'dummy';
        return [
            `${appName}.read`,
            `${appName}.write`,
            `${appName}.admin`
        ];
    }

    getServiceInfo() {
        return {
            url: 'dummy',
            clientId: 'dummy',
            xsappname: 'dummy',
            identityZone: 'dummy',
            tenantId: 'dummy',
            tenantMode: 'dummy',
            configured: true
        };
    }

    getClientCredentials() {
        return {
            client_id: 'dummy',
            client_secret: 'dummy',
            url: 'dummy',
            identityZone: 'dummy',
            tenantMode: 'dummy'
        };
    }
}