import { ApiProperty } from '@nestjs/swagger';

export class CreateDetailInvoiceRequest {
  @ApiProperty({
    description: 'ID of the process',
    example: 1,
    type: Number,
    required: true,
  })
  idProcess: number;

  @ApiProperty({
    description: 'Total value of the invoice',
    example: 1000.0,
    type: Number,
    required: true,
  })
  totalValue: number;

  @ApiProperty({
    description: 'Invoice number',
    example: 'INV-123456',
    type: String,
    required: true,
  })
  invoiceNumber: string;

  @ApiProperty({
    description: 'ID of the entity associated with the invoice',
    example: 1,
    type: Number,
    required: true,
  })
  idEntity: number;

  @ApiProperty({
    description: 'Description of the invoice',
    example: 'Payment for services rendered',
    type: String,
    required: true,
  })
  description: string;

  @ApiProperty({
    description: 'Date of emission of the invoice',
    example: '2023-10-01T00:00:00Z',
    type: Date,
    required: true,
  })
  emissionDate: Date;

  @ApiProperty({
    description: 'Expiration date of the invoice',
    example: '2023-11-01T00:00:00Z',
    type: Date,
    required: true,
  })
  expirationDate: Date;

  @ApiProperty({
    description: 'Email responsible for the invoice',
    example: 'emailresponsability@example.com',
    type: String,
    required: true,
  })
  emailResponsability: string;

  @ApiProperty({
    description: 'ID of the type of payment',
    example: 1,
    type: Number,
    required: true,
  })
  idTypePayment: number;

  @ApiProperty({
    description: 'ID of the document associated with the invoice',
    example: 1,
    type: Number,
    required: true,
  })
  idDocument: number;

  @ApiProperty({
    description: 'ID of the status of the invoice',
    example: 1,
    type: Number,
    required: true,
  })
  idStatus: number;

  constructor(
    idProcess: number,
    totalValue: number,
    invoiceNumber: string,
    idEntity: number,
    description: string,
    emissionDate: Date,
    expirationDate: Date,
    emailResponsability: string,
    idTypePayment: number,
    idDocument: number,
    idStatus: number,
  ) {
    this.idProcess = idProcess;
    this.totalValue = totalValue;
    this.invoiceNumber = invoiceNumber;
    this.idEntity = idEntity;
    this.description = description;
    this.emissionDate = emissionDate;
    this.expirationDate = expirationDate;
    this.emailResponsability = emailResponsability;
    this.idTypePayment = idTypePayment;
    this.idDocument = idDocument;
    this.idStatus = idStatus;
  }
}
