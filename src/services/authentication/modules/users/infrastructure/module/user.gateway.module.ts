import { Module } from '@nestjs/common';
import { UserGatewayController } from '../controller/user.gateway.controller';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { environments } from 'src/settings/environments/environments';

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
            groupId: environments.authUserGroupId,
          },
        },
      },
    ]),
  ],
  controllers: [UserGatewayController],
  providers: [],
  exports: [ClientsModule],
})
export class UserGatewayModule {}
