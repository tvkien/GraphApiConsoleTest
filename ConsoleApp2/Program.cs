using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Graph;
using Microsoft.Identity.Client;
//using Microsoft.Identity.Client;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Npgsql;
using StackExchange.Redis.Extensions.Core;
using StackExchange.Redis.Extensions.Core.Configuration;
using StackExchange.Redis.Extensions.Newtonsoft;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Transactions;

namespace ConsoleApp2
{
    public class Program
    {
        private static HttpClient httpClient = new HttpClient();

        public static async Task Main(string[] args)
        {
            var site = @"https://titanpod2.sharepoint.com/sites/AuvenirDev__EnvironmentPrefix__-0492d920-d5e4-492f-9737-ec1ba422983e/3f26e251-a5d4-4786-bfb8-c6c99108d790";
            var uriSite = new Uri(site);

            var token = await GetAccessTokenAsync();

            try
            {
                var graphServiceClient = new GraphServiceClient(
                               new DelegateAuthenticationProvider(
                                   async (requestMessage) =>
                                   {
                                       requestMessage.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                                   }));

                
                await UploadFile(graphServiceClient, uriSite);


            }
            catch (Exception ex)
            {

            }
           
            Console.WriteLine("Done............");

            Console.ReadKey();
        }

        private static async Task UploadFile(GraphServiceClient graphServiceClient, Uri uriSite)
        {
            DriveItem driveItem = null;
            var siteCollection = await graphServiceClient.Sites.GetByPath(uriSite.AbsolutePath, uriSite.Host).Request().GetAsync();

            var drive = graphServiceClient.Sites[siteCollection.Id].Drive.Root;

            Console.WriteLine("Upload file virus.");

            var timer = new Stopwatch();

            var pathToFile = @"D:\FilesVirus\FileVirus102Mb.zip";
            using (var fileStream = new FileStream(pathToFile, FileMode.Open, FileAccess.Read))
            {
                decimal temp = fileStream.Length / (1024 * 1024);
                timer.Start();
                if (temp <= 4)
                {
                    driveItem = await drive
                      .ItemWithPath("FileVirus102Mb.zip")
                      .Content
                      .Request()
                      .PutAsync<DriveItem>(fileStream);

                    timer.Stop();
                    Console.WriteLine($"Uploaded file {(decimal)temp / 1024} Kb take {timer.Elapsed.ToString()}");
                }
                else
                {
                    driveItem = await UploadLargeFile(drive, fileStream, "FileVirus102Mb.zip");

                    timer.Stop();
                    Console.WriteLine($"Uploaded file {temp} Mb take {timer.Elapsed.ToString()}");
                }
            }

            //Share files
            var sharedWithMe = await graphServiceClient
                .Sites[siteCollection.Id]
                .Drive
                .SharedWithMe()
                .Request()
                .GetAsync();

            //Create share link
            var type = "edit";
            var permission = await graphServiceClient
                .Sites[siteCollection.Id]
                .Drive
                .Items[driveItem.Id]
                .CreateLink(type)
                .Request()
                .PostAsync();

            var terminate = true;
            int index = 1;

            var timer1 = new Stopwatch();
            timer1.Start();

            while (terminate)
            {
                Console.WriteLine($"Verifing file -> Time {index}");
                // Get item
                var fileInfo = await graphServiceClient
                    .Sites[siteCollection.Id]
                    .Drive
                    .Items[driveItem.Id]
                    .Request()
                    .GetAsync();

                var abc = fileInfo.AdditionalData.ContainsKey("malware");

                if (abc)
                {
                    Console.WriteLine("File contain malware!");
                    terminate = false;
                }
                else
                {
                    Console.WriteLine($"Sleep 10 seconds....... Time {index}");
                    index++;
                    Thread.Sleep(10000);
                }
            }

            timer1.Stop();
            Console.WriteLine($"Scan virus file take {timer1.Elapsed.ToString()}");
        }

        private static async Task<DriveItem> UploadLargeFile(
            IDriveItemRequestBuilder driveItemRequestBuilder,
            Stream fileStream,
            string itemPath)
        {
            DriveItem driveItem = null;
            // Use properties to specify the conflict behavior
            // in this case, replace
            var uploadProps = new DriveItemUploadableProperties
            {
                ODataType = null,
                AdditionalData = new Dictionary<string, object>
                {
                    { "@microsoft.graph.conflictBehavior", "replace" }
                }
            };

            // Create the upload session
            // itemPath does not need to be a path to an existing item
            var uploadSession = await driveItemRequestBuilder
                .ItemWithPath(itemPath)
                .CreateUploadSession(uploadProps)
                .Request()
                .PostAsync();

            // Max slice size must be a multiple of 320 KiB
            int maxSliceSize = 320 * 1024;
            var fileUploadTask = new LargeFileUploadTask<DriveItem>(uploadSession, fileStream, maxSliceSize);

            // Create a callback that is invoked after each slice is uploaded
            IProgress<long> progress = new Progress<long>(prog => {
                Console.WriteLine($"Uploaded {prog} bytes of {fileStream.Length} bytes");
            });

            try
            {
                // Upload the file
                var uploadResult = await fileUploadTask.UploadAsync(progress);

                if (uploadResult.UploadSucceeded)
                {
                    // The ItemResponse object in the result represents the
                    // created item.
                    Console.WriteLine($"Upload complete, item ID: {uploadResult.ItemResponse.Id}");
                    driveItem = uploadResult.ItemResponse;
                }
                else
                {
                    Console.WriteLine("Upload failed");
                }
            }
            catch (ServiceException ex)
            {
                Console.WriteLine($"Error uploading: {ex.ToString()}");
            }

            return driveItem;
        }

        private static async Task CreateSubSite(GraphServiceClient graphServiceClient)
        {
            var abc = Guid.NewGuid().ToString();

            var fdsf = await graphServiceClient.Sites.Request().AddAsync(new Site
            {
                Id = abc,
                WebUrl = abc,
                CreatedByUser = new User
                {
                    MailNickname = "admin@titanpod2.onmicrosoft.com"
                },
                DisplayName = abc,
                SiteCollection = new SiteCollection
                {
                    Hostname = "titanpod2.sharepoint.com",

                },
            });
        }

        private static async Task GetListAlert(GraphServiceClient graphServiceClient)
        {
            var alerts = await graphServiceClient.Security.Alerts
                   .Request()
                   .Filter($"Title eq 'Kien Test Alert Malicious Files'")
                   .GetAsync();

            var filter = alerts.Where(x => x.CreatedDateTime.HasValue && x.CreatedDateTime.Value.Date == DateTime.UtcNow.Date);

            SecurityAlertsCollectionPage jsonString = (SecurityAlertsCollectionPage)alerts;

            var jsonString1 = System.Text.Json.JsonSerializer.Serialize(jsonString);

            var abc = alerts.Where(x => x.VulnerabilityStates.Any()).ToList();

        }

        private static async Task<string> GetAccessTokenKienAsync()
        {
            try
            {
                var requestData = new List<KeyValuePair<string, string>>()
                {
                    new KeyValuePair<string, string>("client_id", "192cdaaa-9063-40c5-99a9-b29c154b1716"),
                    new KeyValuePair<string, string>("client_secret", "IEa_.ec_r8_VyFMdG55615.5.qy3l..NJF"),
                    new KeyValuePair<string, string>("scope", "https://graph.microsoft.com/.default"),
                    new KeyValuePair<string, string>("grant_type", "password"),
                    new KeyValuePair<string, string>("username", "admin@titanpod2.onmicrosoft.com"),
                    new KeyValuePair<string, string>("password", "TitanCorpVn@1234")
                };

                var httpRequestMessage = new HttpRequestMessage()
                {
                    RequestUri = new Uri("https://login.microsoftonline.com/31d2192e-fd57-4e9d-9fe4-6524828399c5/oauth2/v2.0/token"),
                    Method = HttpMethod.Post,
                    Content = new FormUrlEncodedContent(requestData)
                };

                var response = await httpClient.SendAsync(httpRequestMessage);
                var dataResponse = await response.Content.ReadAsStringAsync();
                var jsonData = JsonConvert.DeserializeObject<JObject>(dataResponse);
                return jsonData.SelectToken("access_token")?.ToString();
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        private static async Task<string> GetAccessTokenROPCAsync()
        {
            try
            {
                var requestData = new List<KeyValuePair<string, string>>()
                {
                    new KeyValuePair<string, string>("client_id", "e11bb7e9-009a-40e8-9f29-fd922df7d352"),
                    new KeyValuePair<string, string>("client_secret", "t-3u63iwz3ekcG3pk.jbSdE6~2_YyrY_4b"),
                    new KeyValuePair<string, string>("scope", "https://graph.microsoft.com/.default"),
                    new KeyValuePair<string, string>("grant_type", "password"),
                    new KeyValuePair<string, string>("username", "ca_sc_caauvdevspocan@dmchosting.ca"),
                    new KeyValuePair<string, string>("password", "1cXw9k4rgg4sbx!#")
                };

                var httpRequestMessage = new HttpRequestMessage()
                {
                    RequestUri = new Uri("https://login.microsoftonline.com/1ddae48a-90e5-468a-9ac8-244d5b76edf5/oauth2/v2.0/token"),
                    Method = HttpMethod.Post,
                    Content = new FormUrlEncodedContent(requestData)
                };

                var response = await httpClient.SendAsync(httpRequestMessage);
                var dataResponse = await response.Content.ReadAsStringAsync();
                var jsonData = JsonConvert.DeserializeObject<JObject>(dataResponse);
                return jsonData.SelectToken("access_token")?.ToString();
            }
            catch (Exception ex)
            {
                return null;
            }
        }

        private static async Task<string> GetAccessTokenAsync()
        {
            try
            {
                var app = ConfidentialClientApplicationBuilder.Create("572f56d4-35df-4823-a77d-810aa6d30ecd")
                    .WithTenantId("31d2192e-fd57-4e9d-9fe4-6524828399c5")
                    .WithClientSecret("2.w5FcOC6Xps_vL-2qxNSDmoJ36Hg5-Hiw")
                    .Build();

                var scopes = new string[] { "https://graph.microsoft.com/.default" };

                var result = await app.AcquireTokenForClient(scopes).ExecuteAsync();
                return result.AccessToken;
            }
            catch (Exception ex)
            {
                return null;
            }
        }

    }
}
