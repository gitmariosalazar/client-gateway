import { ApiProperty } from '@nestjs/swagger';

export class CreateLogsNotificationsRequest {
  @ApiProperty({
    description: 'Log message for the notification',
    example: 'Notification created successfully',
    required: true,
    type: String,
  })
  log: string;

  @ApiProperty({
    description: 'Detailed message of the notification',
    example: 'This is a test notification message.',
    required: true,
    type: String,
  })
  message: string;

  @ApiProperty({
    description: 'Subject of the notification',
    example: 'New Notification',
    required: true,
    type: String,
  })
  subject: string;

  @ApiProperty({
    description: 'Phone number associated with the notification',
    example: '+593969188817',
    required: true,
    type: String,
  })
  phone: string;

  @ApiProperty({
    description: 'Email address associated with the notification',
    example: 'mariosalazar.ms.10@gmail.com',
    required: true,
    type: String,
  })
  email: string;
  @ApiProperty({
    description: 'Module where the notification is generated',
    example: 'notifications',
    required: true,
    type: String,
  })
  module: string;
  @ApiProperty({
    description: 'Event type of the notification',
    example: 'create',
    required: true,
    type: String,
  })
  eventType: string;
  @ApiProperty({
    description: 'User ID associated with the notification',
    example: 1,
    required: false,
    type: Number,
  })
  userId?: number;
  @ApiProperty({
    description: 'User email associated with the notification',
    example: 'mario@gmail.com',
    required: false,
    type: String,
  })
  userEmail?: string;
  @ApiProperty({
    description: 'IP address from which the notification was generated',
    example: '127.0.0.2',
    required: false,
    type: String,
  })
  ipAddress?: string;
  @ApiProperty({
    description: 'User agent string from which the notification was generated',
    example:
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3',
    required: false,
    type: String,
  })
  userAgent?: string;
  @ApiProperty({
    description: 'HTTP status code associated with the notification',
    example: 200,
    required: false,
    type: Number,
  })
  statusCode?: number;
  @ApiProperty({
    description: 'Kafka topic associated with the notification',
    example: 'notifications-topic',
    required: false,
    type: String,
  })
  kafkaTopic?: string;
  @ApiProperty({
    description: 'Correlation ID for tracing the notification',
    example: '123e4567-e89b-12d3-a456-426614174000',
    required: false,
    type: String,
  })
  correlationId?: string;
  constructor(
    log: string,
    message: string,
    subject: string,
    phone: string,
    email: string,
    module: string,
    eventType: string,
    userId?: number,
    userEmail?: string,
    ipAddress?: string,
    userAgent?: string,
    statusCode?: number,
    kafkaTopic?: string,
    correlationId?: string,
  ) {
    this.log = log;
    this.message = message;
    this.subject = subject;
    this.phone = phone;
    this.email = email;
    this.module = module;
    this.eventType = eventType;
    this.userId = userId;
    this.userEmail = userEmail;
    this.ipAddress = ipAddress;
    this.userAgent = userAgent;
    this.statusCode = statusCode;
    this.kafkaTopic = kafkaTopic;
    this.correlationId = correlationId;
  }
}
