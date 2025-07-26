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
            sessionTimeout: 30000, // Tiempo en ms antes de que el broker considere al consumidor desconectado
            heartbeatInterval: 10000, // Intervalo en ms para enviar heartbeats
            rebalanceTimeout: 60000,
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
