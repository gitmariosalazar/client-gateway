import { Injectable } from '@nestjs/common';

@Injectable()
export class AppService {
  Home(): string {
    return 'Hello World!';
  }
}
