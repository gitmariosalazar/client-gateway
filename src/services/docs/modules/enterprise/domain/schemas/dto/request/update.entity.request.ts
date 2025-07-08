import { ApiProperty } from '@nestjs/swagger';

export class UpdateEntityRequest {
  @ApiProperty({
    description: 'RUC of the entity',
    example: '12345678901',
    required: true,
    type: String,
  })
  ruc: string;

  @ApiProperty({
    description: 'Name of the entity',
    example: 'Example Entity',
    required: true,
    type: String,
  })
  name: string;

  @ApiProperty({
    description: 'Email of the entity',
    example: 'company@example.com',
    required: true,
    type: String,
  })
  email: string;

  @ApiProperty({
    description: 'Cellphone of the entity',
    example: '987654321',
    required: true,
    type: String,
  })
  cellphone: string;

  @ApiProperty({
    description: 'Telephone of the entity',
    example: '123456789',
    required: true,
    type: String,
  })
  telephone: string;

  @ApiProperty({
    description: 'Address of the entity',
    example: '123 Main St, City, Country',
    required: true,
    type: String,
  })
  address: string;

  @ApiProperty({
    description: 'Description of the entity',
    example: 'This is an example entity description.',
    required: true,
    type: String,
  })
  description: string;

  constructor(
    ruc: string,
    name: string,
    email: string,
    cellphone: string,
    telephone: string,
    address: string,
    description: string,
  ) {
    this.ruc = ruc;
    this.name = name;
    this.email = email;
    this.cellphone = cellphone;
    this.telephone = telephone;
    this.address = address;
    this.description = description;
  }
}
