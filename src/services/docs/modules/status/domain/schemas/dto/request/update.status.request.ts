import { ApiProperty } from '@nestjs/swagger';

export class UpdateStatusRequest {
  @ApiProperty({
    description: 'Title of the status',
    example: 'Active',
    type: String,
    required: true,
  })
  name: string;

  @ApiProperty({
    description: 'Description of the status',
    example: 'The status is currently active and operational',
    type: String,
    required: true,
  })
  description: string;

  @ApiProperty({
    description: 'ID of the status type',
    example: 1,
    type: Number,
    required: true,
  })
  idTypeStatus: number;

  constructor(name: string, description: string, idTypeStatus: number) {
    this.name = name;
    this.description = description;
    this.idTypeStatus = idTypeStatus;
  }
}
