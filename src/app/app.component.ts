import { Component } from '@angular/core';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent {
  title = 'Radarduino | 2018';
  connected = 1;

  // Map Component
  zoom = 15;
  lat = -6.5535118;
  lng = 106.7293611;
  markers: Marker[] = [
    {
      lat: -6.5535118,
      lng: 106.7293611,
      label: '127.0.0.1'
    }
  ];
}

// just an interface for type safety.
interface Marker {
  lat: number;
  lng: number;
  label?: string;
}
