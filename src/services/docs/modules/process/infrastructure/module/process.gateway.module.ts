import { Module } from '@nestjs/common';
import { ProcessGatewayController } from '../controller/process.gateway.controller';
import { ClientsModule, Transport } from '@nestjs/microservices';
import { environments } from 'src/settings/environments/environments';

@Module({
  imports: [
    ClientsModule.register([
      {
        name: environments.documentsKafkaClient!,
        transport: Transport.KAFKA,
        options: {
          client: {
            brokers: [`${environments.kafkaBroker}`],
          },
          consumer: {
            groupId: environments.documentsProcessGroupId,
            sessionTimeout: 30000, // Tiempo en ms antes de que el broker considere al consumidor desconectado
            heartbeatInterval: 10000, // Intervalo en ms para enviar heartbeats
            rebalanceTimeout: 60000,
          },
        },
      },
    ]),
  ],
  controllers: [ProcessGatewayController],
  providers: [],
  exports: [ClientsModule],
})
export class ProcessGatewayModule {}
