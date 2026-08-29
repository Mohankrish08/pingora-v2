import { HttpClient } from '@angular/common/http';
import { Injectable, inject } from '@angular/core';
import { Observable } from 'rxjs';

import { environment } from '../../../../environment/environment';
import { RegisterUser } from '../../../models/register';

export interface RegisterResponse {
  user_id: string;
  email: string;
  phone_number: string;
  /** otpauth:// URI to render as a QR code for the authenticator app. */
  totp_provisioning_uri: string;
  email_verified: boolean;
  phone_verified: boolean;
  message: string;
}

@Injectable({ providedIn: 'root' })
export class RegisterService {
  private readonly http = inject(HttpClient);
  private readonly authAPI = environment.authAPI;

  register(data: RegisterUser): Observable<RegisterResponse> {
    return this.http.post<RegisterResponse>(`${this.authAPI}/auth/register`, data, {
      withCredentials: true,
    });
  }
}
