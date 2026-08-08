import { Component, computed, inject, signal } from '@angular/core';
import { CommonModule } from '@angular/common';
import { FormBuilder, FormGroup, ReactiveFormsModule, Validators } from '@angular/forms';
import { RegisterService } from './register.service';

@Component({
  selector: 'app-register',
  standalone: true,
  imports: [CommonModule, ReactiveFormsModule],
  templateUrl: './register.html',
  styleUrl: './register.scss',
})
export class RegisterComponent {
  showPassword = false;
  registerForm: FormGroup;
  registerService = inject(RegisterService);

  constructor(private fb: FormBuilder) {
    this.registerForm = this.fb.group({
      display_name: ['', Validators.required],
      email: ['', [Validators.required, Validators.email]],
      phone_number: ['', [Validators.required, Validators.minLength(10)]],
      password: ['', [Validators.required, Validators.minLength(8)]],
    });
  }


  passwordValue = signal('');

  strength = computed(() => {
    const val = this.passwordValue();
    let s = 0;
    if (val.length > 5) s++;
    if (val.length > 8 && /[A-Z]/.test(val)) s++;
    if (val.length > 10 && /[0-9]/.test(val)) s++;
    if (val.length > 12 && /[^A-Za-z0-9]/.test(val)) s++;
    return s;
  });

  strengthColors = ['#ffb4ab', '#71a1ff', '#10b981', '#4edea3'];

  strengthText = computed(() => {
    switch (this.strength()) {
      case 0: return 'Enter at least 8 characters';
      case 1: return 'Weak - add capital letters';
      case 2: return 'Fair - add numbers';
      case 3: return 'Good - add special symbols';
      case 4: return 'Strong - Excellent password';
      default: return '';
    }
  });

  onPasswordInput(value: string): void {
    this.passwordValue.set(value);
  }

  barColor(index: number): string {
    return index < this.strength() ? this.strengthColors[this.strength() - 1] : 'rgba(60, 74, 66, 0.4)';
  }

  togglePassword(): void {
    this.showPassword = !this.showPassword;
  }

  onSubmit(): void {
    if (this.registerForm.invalid) {
      this.registerForm.markAllAsTouched();
      return;
    }
    const data = this.registerForm.value;
    console.log(this.registerForm.value);
    this.registerService.register(data).subscribe({
      next: (response: any) => {
        console.log("RESP: ", response);
      }
    })
    // wire up to your auth service / navigate to profile-setup step here
  }
}