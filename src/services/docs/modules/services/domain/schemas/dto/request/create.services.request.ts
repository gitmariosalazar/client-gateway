import { ApiProperty } from '@nestjs/swagger';

export class CreateServiceRequest {
  @ApiProperty({
    description: 'Name of the service',
    example: 'Web Hosting',
    required: true,
    type: String,
  })
  name: string;

  @ApiProperty({
    description: 'Description of the service',
    example: 'Provides web hosting services for websites.',
    required: true,
    type: String,
  })
  description: string;

  @ApiProperty({
    description: 'ID of the type of service',
    example: 1,
    required: true,
    type: Number,
  })
  idTypeService: number;

  constructor(name: string, description: string, idTypeService: number) {
    this.name = name;
    this.description = description;
    this.idTypeService = idTypeService;
  }
}
