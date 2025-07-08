import { ApiProperty } from '@nestjs/swagger';

export class CreateTypePaymentRequest {
  @ApiProperty({
    description: 'Title of the type payment',
    example: 'Credit Card',
    type: String,
    required: true,
  })
  name: string;

  @ApiProperty({
    description: 'Description of the type payment',
    example: 'Payment method using credit cards',
    type: String,
    required: true,
  })
  description: string;

  constructor(title: string, description: string) {
    this.name = title;
    this.description = description;
  }
}
