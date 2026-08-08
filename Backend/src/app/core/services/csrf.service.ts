import { Injectable, signal } from "@angular/core";

@Injectable({ providedIn: 'root'})
export class CsrfService {
    private tokenSignal = signal<string | null>(null);

    setToken(token: string): void {
        this.tokenSignal.set(token);
    }

    getToken(): string | null {
        return this.tokenSignal();
    }

    clearToken(): void {
        this.tokenSignal.set(null);
    }
}