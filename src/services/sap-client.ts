import { executeHttpRequest } from '@sap-cloud-sdk/http-client';
import { HttpDestination } from '@sap-cloud-sdk/connectivity';
import { DestinationService } from './destination-service.js';
import { Logger } from '../utils/logger.js';
import { Config } from '../utils/config.js';


export class SAPClient {
    private destination: HttpDestination | null = null;
    private config: Config;

    constructor(
        private destinationService: DestinationService,
        private logger: Logger
    ) {
        this.config = new Config();
    }

    async getDestination(): Promise<HttpDestination> {
        if (!this.destination) {
            this.destination = await this.destinationService.getSAPDestination();
        }
        return this.destination;
    }

    async executeRequest(options: {
        url: string;
        method: 'GET' | 'POST' | 'PATCH' | 'PUT' | 'DELETE';
        data?: unknown;
        headers?: Record<string, string>;
    }) {
        const destination = await this.getDestination();
        
        const requestOptions = {
            method: options.method,
            url: options.url,
            data: options.data,
            headers: {
                'Content-Type': 'application/json',
                'Accept': 'application/json',
                ...options.headers
            }
        };

        try {
            this.logger.debug(`Executing ${options.method} request to ${options.url}`);
            
            if (!destination.url) {
                throw new Error('Destination URL is not configured');
            }
            
            const response = await executeHttpRequest(destination as HttpDestination, requestOptions); 
            
            this.logger.debug(`Request completed successfully`);
            return response;
            
        } catch (error) {
            this.logger.error(`Request failed:`, error);
            throw this.handleError(error);
        }
    }

    async readEntitySet(servicePath: string, entitySet: string, queryOptions?: {
        $filter?: string;
        $select?: string;
        $expand?: string;
        $orderby?: string;
        $top?: number;
        $skip?: number;
    }) {
        let url = `${servicePath}${entitySet}`;
        
        if (queryOptions) {
            const params = new URLSearchParams();
            Object.entries(queryOptions).forEach(([key, value]) => {
                if (value !== undefined && value !== null) {
                    params.set(key, String(value));
                }
            });
            
            if (params.toString()) {
                url += `?${params.toString()}`;
            }
        }

        return this.executeRequest({
            method: 'GET',
            url
        });
    }

    async readEntity(servicePath: string, entitySet: string, key: string) {
        const url = `${servicePath}${entitySet}('${key}')`;
        
        return this.executeRequest({
            method: 'GET',
            url
        });
    }

    async createEntity(servicePath: string, entitySet: string, data: unknown) {
        const url = `${servicePath}${entitySet}`;
        
        return this.executeRequest({
            method: 'POST',
            url,
            data
        });
    }

    async updateEntity(servicePath: string, entitySet: string, key: string, data: unknown) {
        const url = `${servicePath}${entitySet}('${key}')`;
        
        return this.executeRequest({
            method: 'PATCH',
            url,
            data
        });
    }

    async deleteEntity(servicePath: string, entitySet: string, key: string) {
        const url = `${servicePath}${entitySet}('${key}')`;
        
        return this.executeRequest({
            method: 'DELETE',
            url
        });
    }

    private handleError(error: unknown): Error {
        if (
            typeof error === 'object' &&
            error !== null &&
            'rootCause' in error &&
            (error as { rootCause?: { response?: { status: number; data?: { error?: { message?: string } }; statusText?: string } } }).rootCause?.response
        ) {
            const response = (error as { rootCause: { response: { status: number; data?: { error?: { message?: string } }; statusText?: string } } }).rootCause.response;
            return new Error(`SAP API Error ${response.status}: ${response.data?.error?.message || response.statusText}`);
        }
        return error instanceof Error ? error : new Error(String(error));
    }
}
