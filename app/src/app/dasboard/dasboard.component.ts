import { HttpClient } from '@angular/common/http';
import { Component, inject } from '@angular/core';
import { map } from 'rxjs';

@Component({
  selector: 'app-dasboard',
  imports: [],
  templateUrl: './dasboard.component.html',
  styleUrl: './dasboard.component.css'
})
export class DasboardComponent {
  private readonly httpClient = inject(HttpClient)
  constructor() {
    this.httpClient.get('http://localhost:8081/api/profile', {
      headers: {
        'Authorization': `${localStorage.getItem('token')}`
        }
    }).pipe(map((response) => {
      console.log(response)
    },
    )).subscribe()
  }
}
