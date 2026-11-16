import { bootstrapApplication } from '@angular/platform-browser';
import { appConfig } from './app/app.config';
import { OwaspLabComponent } from './app/owasp-lab.component';

bootstrapApplication(OwaspLabComponent, appConfig)
  .catch((err) => console.error(err));

