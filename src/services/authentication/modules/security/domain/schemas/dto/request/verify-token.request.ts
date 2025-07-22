import { ApiProperty } from '@nestjs/swagger';

export class VerifyTokenRequest {
  @ApiProperty({
    description: 'The JWT token to verify',
    example: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...',
  })
  auth_token: string;

  @ApiProperty({
    description: 'The IP address of the user making the request',
    example: '192.168.1.1',
  })
  ipAddress?: string;

  constructor(auth_token: string, ipAddress?: string) {
    this.auth_token = auth_token;
    this.ipAddress = ipAddress;
  }
}
