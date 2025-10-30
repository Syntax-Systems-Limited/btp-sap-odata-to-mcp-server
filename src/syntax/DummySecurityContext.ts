import { SecurityContext } from '@sap/xssec';

export class DummySecurityContext implements SecurityContext {
    getUserName(): string {
        return 'dummy';
    }
    getEmail(): string {
        return 'dummy';
    }
    getGivenName(): string {
        return 'dummy';
    }
    getFamilyName(): string {
        return 'dummy';
    }
    getSubdomain(): string {
        return 'dummy';
    }
    getClientId(): string {
        return 'dummy';
    }
    getExpirationDate(): Date {
        return new Date('1900-01-01');
    }
    getGrantedScopes(): string[] {
        return ['dummy'];
    }
    checkScope(scope: string): boolean {
        return true;
    }
    checkLocalScope(scope: string): boolean {
        return true;
    }
    getToken(): string {
        return 'dummy';
    }
    getHdbToken(): string {
        return 'dummy';
    }
    getAppToken(): string {
        return 'dummy';
    }
    getIdentityZone(): string {
        return 'dummy';
    }
    getSubaccountId(): string {
        return 'dummy';
    }
    isInForeignMode(): boolean {
        return false;
    }
}