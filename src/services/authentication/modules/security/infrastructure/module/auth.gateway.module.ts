import { Module } from '@nestjs/common';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { environments } from 'src/settings/environments/environments';
import { AuthGatewayController } from '../controller/auth.gateway.controller';

@Module({
  imports: [
    ClientsModule.register([
      {
        name: environments.authenticationKafkaClient!,
        transport: Transport.KAFKA,
        options: {
          client: {
            brokers: [`${environments.kafkaBroker}`],
          },
          consumer: {
            groupId: environments.authSecurityGroupId,
          },
        },
      },
      {
        name: environments.notificationKafkaClient!,
        transport: Transport.KAFKA,
        options: {
          client: {
            brokers: [`${environments.kafkaBroker}`],
          },
          consumer: {
            groupId: environments.notificationNotificationGroupId,
          },
        },
      },
    ]),
  ],
  controllers: [AuthGatewayController],
  providers: [],
  exports: [ClientsModule],
})
export class AuthGatewayModule {}
