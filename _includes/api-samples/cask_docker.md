```json
{
  "token": "docker",
  "full_token": "docker",
  "tap": "homebrew/cask",
  "name": [
    "Docker Desktop",
    "Docker Community Edition",
    "Docker CE"
  ],
  "desc": "App to build and share containerized applications and microservices",
  "homepage": "https://www.docker.com/products/docker-desktop",
  "url": "https://desktop.docker.com/mac/main/amd64/91374/Docker.dmg",
  "appcast": null,
  "version": "4.14.0,91374",
  "versions": {},
  "installed": null,
  "outdated": false,
  "sha256": "f554d67e1189efdc5e85e4c28bc4b82a979914016bfb5cc83cde719d557ce062",
  "artifacts": [
    {
      "uninstall": [
        {
          "delete": [
            "/Library/PrivilegedHelperTools/com.docker.vmnetd",
            "$(brew --prefix)/bin/com.docker.cli",
            "$(brew --prefix)/bin/docker-compose-v1",
            "$(brew --prefix)/bin/docker-compose",
            "$(brew --prefix)/bin/docker-credential-desktop",
            "$(brew --prefix)/bin/docker-credential-ecr-login",
            "$(brew --prefix)/bin/docker-credential-osxkeychain",
            "$(brew --prefix)/bin/docker",
            "$(brew --prefix)/bin/hub-tool",
            "$(brew --prefix)/bin/hyperkit",
            "$(brew --prefix)/bin/kubectl.docker",
            "$(brew --prefix)/bin/kubectl",
            "$(brew --prefix)/bin/notary",
            "$(brew --prefix)/bin/vpnkit",
            "$(brew --prefix)/share/zsh/site-functions/_docker",
            "$(brew --prefix)/share/zsh/site-functions/_docker_compose",
            "$(brew --prefix)/share/fish/vendor_completions.d/docker.fish",
            "$(brew --prefix)/share/fish/vendor_completions.d/docker-compose.fish",
            "$(brew --prefix)/etc/bash_completion.d/docker",
            "$(brew --prefix)/etc/bash_completion.d/docker-compose"
          ],
          "launchctl": [
            "com.docker.helper",
            "com.docker.vmnetd"
          ],
          "quit": "com.docker.docker"
        }
      ]
    },
    {
      "app": [
        "Docker.app"
      ]
    },
    {
      "binary": [
        "/Applications/Docker.app/Contents/Resources/etc/docker-compose.bash-completion",
        {
          "target": "$(brew --prefix)/etc/bash_completion.d/docker-compose"
        }
      ]
    },
    {
      "binary": [
        "/Applications/Docker.app/Contents/Resources/etc/docker.zsh-completion",
        {
          "target": "$(brew --prefix)/share/zsh/site-functions/_docker"
        }
      ]
    },
    {
      "binary": [
        "/Applications/Docker.app/Contents/Resources/etc/docker.fish-completion",
        {
          "target": "$(brew --prefix)/share/fish/vendor_completions.d/docker.fish"
        }
      ]
    },
    {
      "binary": [
        "/Applications/Docker.app/Contents/Resources/etc/docker-compose.fish-completion",
        {
          "target": "$(brew --prefix)/share/fish/vendor_completions.d/docker-compose.fish"
        }
      ]
    },
    {
      "binary": [
        "/Applications/Docker.app/Contents/Resources/etc/docker-compose.zsh-completion",
        {
          "target": "$(brew --prefix)/share/zsh/site-functions/_docker_compose"
        }
      ]
    },
    {
      "binary": [
        "/Applications/Docker.app/Contents/Resources/etc/docker.bash-completion",
        {
          "target": "$(brew --prefix)/etc/bash_completion.d/docker"
        }
      ]
    },
    {
      "zap": [
        {
          "trash": [
            "$(brew --prefix)/bin/docker-compose.backup",
            "$(brew --prefix)/bin/docker.backup",
            "~/.docker",
            "~/Library/Application Scripts/com.docker.helper",
            "~/Library/Application Support/com.bugsnag.Bugsnag/com.docker.docker",
            "~/Library/Application Support/Docker Desktop",
            "~/Library/Caches/com.docker.docker",
            "~/Library/Caches/com.plausiblelabs.crashreporter.data/com.docker.docker",
            "~/Library/Caches/KSCrashReports/Docker",
            "~/Library/Containers/com.docker.docker",
            "~/Library/Containers/com.docker.helper",
            "~/Library/Group Containers/group.com.docker",
            "~/Library/HTTPStorages/com.docker.docker.binarycookies",
            "~/Library/Logs/Docker Desktop",
            "~/Library/Preferences/com.docker.docker.plist",
            "~/Library/Preferences/com.electron.docker-frontend.plist",
            "~/Library/Preferences/com.electron.dockerdesktop.plist",
            "~/Library/Saved Application State/com.electron.docker-frontend.savedState",
            "~/Library/Saved Application State/com.electron.dockerdesktop.savedState"
          ],
          "rmdir": [
            "~/Library/Caches/com.plausiblelabs.crashreporter.data",
            "~/Library/Caches/KSCrashReports"
          ]
        }
      ]
    }
  ],
  "caveats": null,
  "depends_on": {
    "macos": {
      ">=": [
        "10.15"
      ]
    }
  },
  "conflicts_with": {
    "formula": [
      "docker",
      "docker-completion",
      "docker-compose",
      "docker-compose-completion",
      "docker-credential-helper-ecr",
      "hyperkit",
      "kubernetes-cli"
    ]
  },
  "container": null,
  "auto_updates": true,
  "variations": {
    "arm64_ventura": {
      "url": "https://desktop.docker.com/mac/main/arm64/91374/Docker.dmg",
      "sha256": "38be55c1dc0686e17c761c4953892ff21ffc5cddef19171e428ca2c0224f3b95"
    },
    "arm64_monterey": {
      "url": "https://desktop.docker.com/mac/main/arm64/91374/Docker.dmg",
      "sha256": "38be55c1dc0686e17c761c4953892ff21ffc5cddef19171e428ca2c0224f3b95"
    },
    "arm64_big_sur": {
      "url": "https://desktop.docker.com/mac/main/arm64/91374/Docker.dmg",
      "sha256": "38be55c1dc0686e17c761c4953892ff21ffc5cddef19171e428ca2c0224f3b95"
    }
  },
  "analytics": {
    "install": {
      "30d": {
        "docker": 28167
      },
      "90d": {
        "docker": 78301
      },
      "365d": {
        "docker": 308358
      }
    }
  },
  "generated_date": "2022-11-16"
}
```