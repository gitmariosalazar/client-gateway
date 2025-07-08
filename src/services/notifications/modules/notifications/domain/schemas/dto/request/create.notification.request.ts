import { ApiProperty } from '@nestjs/swagger';

export class CreateNotificationRequest {
  @ApiProperty({
    description: 'Email address for the notification',
    example: 'mario10salazar.ms.10@gmail.com',
    required: true,
    type: String,
  })
  email: string;

  @ApiProperty({
    description: 'Phone number for the notification',
    example: '+593969188817',
    required: true,
    type: String,
  })
  phone: string;

  @ApiProperty({
    description: 'Subject of the notification',
    example: 'New Notification',
    required: true,
    type: String,
  })
  subject: string;

  @ApiProperty({
    description: 'Message content of the notification',
    example: 'This is a test notification message.',
    required: true,
    type: String,
  })
  message: string;

  @ApiProperty({
    description: 'Type of notification ID',
    example: 1,
    required: true,
    type: Number,
  })
  idTypeNotification: number;

  attempts?: number;

  sentAt?: Date;

  @ApiProperty({
    description: 'Process code associated with the notification',
    example: 1,
    required: true,
    type: Number,
  })
  processCode: number;

  @ApiProperty({
    description: 'Priority ID of the notification',
    example: 1,
    required: true,
    type: Number,
  })
  idPriority: number;

  @ApiProperty({
    description: 'Status ID of the notification',
    example: 1,
    required: true,
    type: Number,
  })
  idStatus: number;
  logsNotification?: any;

  constructor(
    email: string,
    phone: string,
    subject: string,
    message: string,
    idTypeNotification: number,
    attempts: number = 0,
    sentAt: Date = new Date(),
    processCode: number,
    idPriority: number,
    idStatus: number,
    logsNotification?: any,
  ) {
    this.email = email;
    this.phone = phone;
    this.subject = subject;
    this.message = message;
    this.idTypeNotification = idTypeNotification;
    this.attempts = attempts;
    this.sentAt = sentAt;
    this.processCode = processCode;
    this.idPriority = idPriority;
    this.idStatus = idStatus;
    this.logsNotification = logsNotification || [];
  }
}
