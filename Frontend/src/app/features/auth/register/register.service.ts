import { Injectable } from "@angular/core";
import { environment } from "../../../../environment/environment";
import { RegisterUser } from "../../../models/register";
import { HttpClient } from "@angular/common/http";

@Injectable({
  providedIn: 'root'
})

export class RegisterService {

    // API
    authAPI = environment.authAPI;

    // constructor
    constructor(private http: HttpClient) {

    }

    // routes
    register(data: RegisterUser) {
        return this.http.post(`${this.authAPI}/auth/register`, data);
    }
}
