import { Module } from '@nestjs/common';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { environments } from 'src/settings/environments/environments';
import { UserTypeGatewayController } from '../controller/user-type.gateway.controller';

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
            groupId: environments.authUserTypeGroupId,
          },
        },
      },
    ]),
  ],
  controllers: [UserTypeGatewayController],
  providers: [],
  exports: [ClientsModule],
})
export class UserTypeGatewayModule {}
