cask "gitfox" do
  version "2.3.2,6627"
  sha256 "28cdc51d9227868bea7a0b6e92422f4ed3b58fb2d813edd73ad7930f92b575f0"

  url "https://storage.googleapis.com/gitfox/builds/retail/#{version.csv.second}/Gitfox.#{version.csv.second}.zip",
      verified: "storage.googleapis.com/gitfox/"
  name "Gitfox"
  desc "Git client"
  homepage "https://www.gitfox.app/"

  livecheck do
    url "https://storage.googleapis.com/gitfox/Gitfox.latest.stable.zip"
    strategy :extract_plist
  end

  auto_updates true
  depends_on macos: ">= :big_sur"

  app "Gitfox.app"
  binary "#{appdir}/Gitfox.app/Contents/SharedSupport/bin/gitfox-cli", target: "gitfox"

  zap trash: [
    "~/Library/Application Support/com.bytieful.Gitfox",
    "~/Library/Application Support/com.bytieful.Gitfox-retail",
    "~/Library/Application Support/Gitfox",
    "~/Library/Caches/com.bytieful.Gitfox",
    "~/Library/Caches/com.bytieful.Gitfox-retail",
    "~/Library/Caches/com.crashlytics.data/com.bytieful.Gitfox",
    "~/Library/Preferences/com.bytieful.Gitfox.*",
    "~/Library/Preferences/com.bytieful.Gitfox-retail.plist",
    "~/Library/Saved Application State/com.bytieful.Gitfox-retail.savedState",
    "~/Library/WebKit/com.bytieful.Gitfox",
  ]
end
