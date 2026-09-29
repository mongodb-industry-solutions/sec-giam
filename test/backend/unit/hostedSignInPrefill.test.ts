// The optional prefill hints on the authorization endpoint: `login_hint`, and the demo's
// `prefill_password`.
//
// Both exist so a hosted sign-in can arrive with its fields already filled, which is what the
// LeafyPay-era integration relied on and what an integrator starting from that URL still sends. The
// endpoint is free to ignore an unknown query parameter, so dropping one of these is a silent
// regression: the flow still completes, the person just faces an empty form. Declared in the
// document here, so the support is part of the contract rather than an implementation detail.
import { describe, it, expect, beforeAll, afterAll } from 'vitest';
import type { FastifyInstance } from 'fastify';
import { buildOpenApiApp, type OpenApiDocument } from '../../../backend/src/shared/services/openapi';
import { redactSecrets } from '../../../backend/src/modules/audit/services/securityEvent.service';

let app: FastifyInstance | undefined;
let document: OpenApiDocument;

beforeAll(async () => { ({ app, document } = await buildOpenApiApp()); });
afterAll(async () => { await app?.close(); });

describe('the authorization endpoint accepts the hosted sign-in prefill hints', () => {
  const parameters = () => {
    const path = document.paths?.['/api/v1/realms/{realm}/protocol/oidc/auth'];
    const operation = path?.get as { parameters?: Array<{ name: string; in: string }> } | undefined;
    return operation?.parameters ?? [];
  };

  it('documents login_hint, so a client naming who is signing in is not guessing', () => {
    const hint = parameters().find((p) => p.name === 'login_hint' && p.in === 'query');
    expect(hint, 'login_hint is not documented on the authorization endpoint').toBeTruthy();
  });

  it('documents prefill_password, the non-standard one a demo integration sends', () => {
    const prefill = parameters().find((p) => p.name === 'prefill_password' && p.in === 'query');
    expect(prefill, 'prefill_password is not documented on the authorization endpoint').toBeTruthy();
  });

  /**
   * The one limit placed on the non-standard parameter.
   *
   * It is honoured in every deployment, because a simple integration is the whole point of it. What
   * is NOT acceptable is the credential outliving the redirect it came in on, so the trail's sink
   * redacts it under its own name as well as under `password`.
   */
  it('never lets a prefilled password reach the trail', () => {
    const redacted = redactSecrets({
      prefill_password: 'demo-password',
      login_hint: 'luis.fernandez@back.es',
    }) as Record<string, unknown>;

    expect(redacted.prefill_password).toBe('[redacted]');
    // The control: the hint is not a credential and is worth having in a trail.
    expect(redacted.login_hint).toBe('luis.fernandez@back.es');
  });
});
