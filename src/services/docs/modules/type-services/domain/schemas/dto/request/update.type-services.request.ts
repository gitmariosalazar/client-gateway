import { ApiProperty } from '@nestjs/swagger';

export class UpdateTypeServicesRequest {
  @ApiProperty({
    example: 'Web Development',
    description: 'The name of the type of service',
    required: true,
    type: String,
  })
  name: string;

  @ApiProperty({
    example:
      'Services related to web development including design, coding, and deployment.',
    description: 'A brief description of the type of service',
    required: true,
    type: String,
  })
  description: string;

  constructor(name: string, description: string) {
    this.name = name;
    this.description = description;
  }
}
