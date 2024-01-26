# Ajout de l'authentification Keycloak dans un projet Symfony 7

## Prérequis
- Un projet Symfony 7 en webapp


## Installation de KnpUOAuth2ClientBundle

- Installation de la librairie
```Bash
composer require knpuniversity/oauth2-client-bundle
```

- Installation du provider Keycloak
```Bash
composer require stevenmaguire/oauth2-keycloak
```

## Configuration du provider Keycloak

- Se rendre dans le fichier /config/packages/knpu_oauth2_client.yaml

- Insérer ce snippet :

```yaml
knpu_oauth2_client:
    clients:
        keycloak:
            type: keycloak
            auth_server_url: "%env(KEYCLOAK_APP_URL)%"
            realm: "%env(KEYCLOAK_REALM)%"
            client_id: "%env(KEYCLOAK_CLIENTID)%"
            client_secret: "%env(KEYCLOAK_SECRET)%"
            redirect_route: "oauth_callback"
            version: "22.0.4"
```

## Création de la classe User

- Générer la classe USer avec la commande suivante : 
```Bash
php bin/console make:user 
```

- Ajouter un champ keycloakId et un champ fullname

```Bash
php bin/console make:entity User
```

- Générer une migration
```Bash
php bin/console make:migration
```

- Exécuter la migration
```Bash
php bin/console d:m:m
```

## Génération des routes nécessaires

- Générer un controller pour ajouter les routes
```Bash
php bin/console make:controller OauthController
```

- Ajouter le code suivant : 
```PHP
<?php

namespace App\Controller;

use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Client\Provider\KeycloakClient;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Attribute\Route;

#[Route('/oauth', name: 'oauth_')]
class OauthController extends AbstractController
{
    public function __construct(
        private readonly ClientRegistry $clientRegistry
    ) {
    }

    #[Route('/login', name: 'login')]
    public function login(): Response
    {
        return $this->getKeycloakClient()->redirect(['roles', 'profile', 'email', 'openid']);
    }

    #[Route('/callback', name: 'callback')]
    public function callback(Request $request): void
    {
    }

    #[Route('/logout', name: 'logout')]
    public function logout(): Response
    {
    }
    private function getKeycloakClient(): KeycloakClient
    {
        /** @var KeycloakClient **/
        return $this->clientRegistry->getClient("keycloak");
    }
}
```

- Générer un Authenticator symfony vide
```Bash
php bin/console make:auth 
```

- Ajouter le code suivant :
```PHP
<?php

namespace App\Security;

use App\Entity\User;
use Doctrine\ORM\EntityManagerInterface;
use KnpU\OAuth2ClientBundle\Client\ClientRegistry;
use KnpU\OAuth2ClientBundle\Security\Authenticator\OAuth2Authenticator;
use Stevenmaguire\OAuth2\Client\Provider\KeycloakResourceOwner;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Core\Authentication\Token\TokenInterface;
use Symfony\Component\Security\Core\Exception\AuthenticationException;
use Symfony\Component\Security\Http\Authenticator\Passport\Badge\UserBadge;
use Symfony\Component\Security\Http\Authenticator\Passport\Passport;
use Symfony\Component\Security\Http\Authenticator\Passport\SelfValidatingPassport;
use Symfony\Component\Security\Http\EntryPoint\AuthenticationEntryPointInterface;

class GPTKeycloakAuthenticator extends OAuth2Authenticator implements AuthenticationEntryPointInterface
{
    public function __construct(
        private readonly ClientRegistry $clientRegistry,
        private readonly EntityManagerInterface $entityManager,
        private readonly RouterInterface $router
    )
    {
    }

    public function supports(Request $request): ?bool
    {
        return $request->attributes->get("_route") === "oauth_callback";
    }

    public function authenticate(Request $request): Passport
    {
        $client = $this->clientRegistry->getClient('keycloak');
        $accessToken = $this->fetchAccessToken($client);

        return new SelfValidatingPassport(
            new UserBadge($accessToken->getToken(), function() use ($accessToken, $client) {
                /** @var KeycloakResourceOwner $keycloakUser */
                $keycloakUser = $client->fetchUserFromToken($accessToken);

                $email = $keycloakUser->getEmail();
                $existingUser = $this->entityManager->getRepository(User::class)->findOneBy(['keycloakId' => $keycloakUser->getId()]);

                if ($existingUser) {
                    $existingUser->setFullname($keycloakUser->getName());
                    $existingUser->setEmail($email);
                    $this->entityManager->persist($existingUser);
                    $this->entityManager->flush();

                    return $existingUser;
                }

                $user = $this->entityManager->getRepository(User::class)->findOneBy(['email' => $email]);

                if (!$user) {
                    $user = new User();
                    $user->setEmail($email);
                }
                $user->setFullname($keycloakUser->getName());
                $user->setKeycloakId($keycloakUser->getId());
                $this->entityManager->persist($user);
                $this->entityManager->flush();

                return $user;
            })
        );
    }

    public function onAuthenticationSuccess(Request $request, TokenInterface $token, string $firewallName): ?Response
    {
        return new RedirectResponse($this->router->generate("app_home"));
    }

    public function onAuthenticationFailure(Request $request, AuthenticationException $exception): ?Response
    {
        $message = strtr($exception->getMessageKey(), $exception->getMessageData());

        return new Response($message, Response::HTTP_FORBIDDEN);
    }

    public function start(Request $request, AuthenticationException $authException = null): Response
    {
        return new RedirectResponse($this->router->generate("oauth_login"), Response::HTTP_TEMPORARY_REDIRECT);
    }
}
```

- Ajouter les parameters suivant dans le services.yaml
```yaml
parameters:
  keycloak.base_url: '%env(KEYCLOAK_APP_URL)%'
  keycloak.realm: '%env(KEYCLOAK_REALM)%'
  keycloak.client_id: '%env(KEYCLOAK_CLIENTID)%'
```

- Configurer la route de logout dans le security.yaml et le provider pour la classe User
```yaml
security:
  providers:
    app_user_provider:
    entity:
      class: App\Entity\User
      property: email
  firewalls:
    main:
      logout:
        path: /oauth/logout
```

- Ajouter un EventSubscriver pour le logout pour se déconnecter côté keycloak en même temps
```
php bin/console make:listener LogoutSubscriber Symfony\Component\Security\Http\Event\LogoutEvent
```

- Y mettre le code suivant : 

```PHP
<?php

namespace App\EventSubscriber;

use Symfony\Component\DependencyInjection\ParameterBag\ParameterBagInterface;
use Symfony\Component\EventDispatcher\EventSubscriberInterface;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;
use Symfony\Component\Routing\RouterInterface;
use Symfony\Component\Security\Http\Event\LogoutEvent;

class LogoutSubscriber implements EventSubscriberInterface
{
    public function __construct(
        private readonly ParameterBagInterface $parameterBag,
        private readonly RouterInterface $router
    ) {
    }

    public function onLogoutEvent(LogoutEvent $event): void
    {
        $response = new RedirectResponse(
            $this->generateKeycloakLogoutUrl(),
            Response::HTTP_SEE_OTHER
        );
        $event->setResponse($response);
    }

    public static function getSubscribedEvents(): array
    {
        return [
            LogoutEvent::class => 'onLogoutEvent',
        ];
    }

    private function generateKeycloakLogoutUrl(): string
    {
        return sprintf("%s/realms/%s/protocol/openid-connect/logout?post_logout_redirect_uri=%s&client_id=%s", $this->parameterBag->get("keycloak.base_url"), $this->parameterBag->get("keycloak.realm"), urlencode($this->router->generate("app_home", [], UrlGeneratorInterface::ABSOLUTE_URL)), $this->parameterBag->get("keycloak.client_id"));
    }
}
```

## Ajouter les variables d'environnement

- Ajouter les 4 variables d'environnement suivante dans le .env.local (Adaptez les valeurs selon votre cas)
```
KEYCLOAK_SECRET=mon_secret
KEYCLOAK_CLIENTID=keycloak_client_id
KEYCLOAK_REALM=keycloak_realm
KEYCLOAK_APP_URL=https://keycloak.example.com
```

## Profitez

- Url de connexion : [/oauth/login](http://localhost:8000/oauth/login)
- Url de déconnexion : [/oauth/logout](http://localhost:8000/oauth/logout)