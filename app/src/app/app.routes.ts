import { Routes } from '@angular/router';
import { SignupFormComponent } from './signup-form/signup-form.component';
import { LoginComponent } from './login/login.component';

export const routes: Routes = [
    {
        path: '',
        redirectTo: "/dashboard",
        pathMatch: 'full'
    }, {
        path: 'signup',
        component: SignupFormComponent
    }, {
        path: 'login',
        component: LoginComponent
    },
    {
        path: 'dashboard',
        loadComponent: () => import('./dasboard/dasboard.component').then(m => m.DasboardComponent )
    }

];
