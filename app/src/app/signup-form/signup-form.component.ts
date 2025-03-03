import { Component, inject } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { HttpClient } from '@angular/common/http';
import { MatSnackBar } from '@angular/material/snack-bar';
import { Router } from '@angular/router';
import { DateAdapter } from '@angular/material/core';
import { MatDatepickerModule } from '@angular/material/datepicker';
import { MatInputModule } from '@angular/material/input';
import { MatButtonModule } from '@angular/material/button';
import { MatSelectModule } from '@angular/material/select';
import { MatFormFieldModule } from '@angular/material/form-field';
import { MatIconModule } from '@angular/material/icon';
import { MatCardModule } from '@angular/material/card';
import { MatSnackBarModule } from '@angular/material/snack-bar';
import { ReactiveFormsModule } from '@angular/forms';
import { CommonModule } from '@angular/common';
import { MatStepperModule } from '@angular/material/stepper';
import dayjs from 'dayjs'

@Component({
  selector: 'app-signup-form',
  standalone: true,
  imports: [
    CommonModule,
    ReactiveFormsModule,
    MatSnackBarModule,
    MatCardModule,
    MatFormFieldModule,
    MatInputModule,
    MatButtonModule,
    MatSelectModule,
    MatDatepickerModule,
    MatIconModule,
    MatInputModule,
    MatDatepickerModule,
    MatStepperModule
  ],
  templateUrl: './signup-form.component.html',
  styleUrls: ['./signup-form.component.css']
})
export class SignupFormComponent {
  form: FormGroup;
  formNameGroup: FormGroup;
  formPasswordGroup: FormGroup;
  formAddressGroup: FormGroup;
  formFileGroup: FormGroup;
  isLinear = true;
  // Handle file selection
  selectedFile!: any;
  previewUrl: string | ArrayBuffer | null = null;

  private fb = inject(FormBuilder);
  private http = inject(HttpClient);
  private snackBar = inject(MatSnackBar);
  private router = inject(Router);

  constructor() {
    this.form = this.fb.group({
      name: ['test user', Validators.required],
      email: ['testuser@yopmail.com', [Validators.required, Validators.email]],
      username: ['@testuser', Validators.required],
      phone: ['1234567890', [Validators.required, Validators.pattern('^[0-9]{10}$')]],
      date_of_birth: ['3/12/2025', Validators.required],
      gender: ['Male', Validators.required],
      password: ['A', [Validators.required, Validators.minLength(8)]],
      confirm_password: ['', Validators.required],
      profile_pic: [null]
    });
    this.formNameGroup = this.fb.group({
      name: ['test user', Validators.required],
      email: ['testuser@yopmail.com', [Validators.required, Validators.email]],
      username: ['@testuser', Validators.required],
      phone: ['1234567890', [Validators.required, Validators.pattern('^[0-9]{10}$')]],
      date_of_birth: [new Date(), Validators.required],
      gender: ['Male', Validators.required],
    });

    this.formPasswordGroup = this.fb.group({
      password: ['Access@#$1234', [Validators.required, Validators.minLength(8)]],
      confirm_password: ['Access@#$1234', Validators.required]
    });

    this.formAddressGroup = this.fb.group({
      address: ['damm', Validators.required],
      country: ['Us', Validators.required],
      state: ['Mexico', Validators.required],
      city: ['MX', Validators.required],
      pincode: ['12345', Validators.required]

    });

    this.formFileGroup = this.fb.group({
      profile_pic: [null]
    });
  }

  onSubmit() {
    if (this.formNameGroup.invalid || this.formPasswordGroup.invalid || this.formAddressGroup.invalid || this.formFileGroup.invalid) {
      return;
    }

    const formData = new FormData();
    formData.append('profile_pic', this.selectedFile);

    this.http.post('http://localhost:8081/api/upload', formData).subscribe({
      next: (response: any) => {
        console.log(response);
        this.formFileGroup.get('profile_pic')?.setValue(response.filepath);
        // Handle the response 
      },
      error: (error: any) => {
        console.error(error);
      },
      complete: () => {
        const formattedDate = this.formNameGroup.value.date_of_birth
          ? dayjs(this.formNameGroup.value.date_of_birth)
            .format('YYYY-MM-DD[T]HH:mm:ss[Z]') // Format with timezone and ISO 8601 style
          : '';

        this.formNameGroup.get('date_of_birth')?.setValue(formattedDate);

        // Use .value to extract form values and remove circular references
        const payload = {
          ...this.formNameGroup.value,
          ...this.formPasswordGroup.value,
          ...this.formAddressGroup.value,
          ...this.formFileGroup.value,
        };

        this.http.post('http://localhost:8081/api/signup', payload).subscribe(response => {
          this.snackBar.open('Signup Successful', 'Close', { duration: 3000 });
          this.router.navigate(['/login']);
        }, error => {
          console.error(error);
          this.snackBar.open('Signup Failed', 'Close', { duration: 3000 });
        });
      }
      });
 
  }




  onFileChange(event: any): void {
    const file = event.target.files[0];
    if (file) {
      this.selectedFile = file;
      this.formFileGroup.get('profile_pic')?.setValue(file);
      this.previewUrl = URL.createObjectURL(file);
    }
  }

  mobeToNextStep(): void {
    console.log(
      'fff',
      this.formNameGroup.value

    );
    
  }

}
