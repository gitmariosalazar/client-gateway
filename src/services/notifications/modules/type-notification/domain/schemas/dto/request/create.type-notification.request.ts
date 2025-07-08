import { ApiProperty } from '@nestjs/swagger';

export class CreateTypeNotificationRequest {
  @ApiProperty({
    description: 'Name of the type of notification',
    example: 'New Message',
    required: true,
    type: String,
  })
  name: string;

  @ApiProperty({
    description: 'Description of the type of notification',
    example: 'Notification for new messages received',
    required: true,
    type: String,
  })
  description: string;
}
