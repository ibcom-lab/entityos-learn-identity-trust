/*
	Used to set up OAuth2 connection between entityOS space and Microsoft service
	Using OAuth2

	ie. get the refresh_token and store in on entityOS.cloud.

	Depends on;
	https://learn-next.entityos.cloud/learn-function-automation

	---

	This is a lambda compliant node app with a wrapper to process data from API Gateway & respond to it.

	To run it on your local computer your need to install
	https://www.npmjs.com/package/lambda-local and then run as:

	API Gateway docs:
	- https://docs.aws.amazon.com/lambda/latest/dg/nodejs-handler.html
	
	!!! In production make sure the settings.json is unrestricted data with functional restriction to setup_user
	!!! The apiKey user has restricted data (based on relationships) and functional access

	Run;
	lambda-local -l index.js -t 9000 -e event-get-consent.json
	lambda-local -l index.js -t 9000 -e event-set-consent.json

	entityos.cloud.search( 
	{
		object: 'core_protect_key',
		fields: ['object', 'objectcontext', 'title', 'key', 'notes']
	});

	zip -r ../entityos-learn-identity-trust.zip *
*/

exports.handler = function (event, context, callback)
{
	var entityos = require('entityos')
	var _ = require('lodash')
	var moment = require('moment');
	var msal = require('@azure/msal-node');

	console.log(event)

	entityos.set(
	{
		scope: 'app',
		context: 'event',
		value: event
	});

	entityos.set(
	{
		scope: 'app',
		context: 'context',
		value: context
	});

	/*
		Use promise to responded to API Gateway once all the processing has been completed.
	*/

	const promise = new Promise(function(resolve, reject)
	{	
		var site = '000';
		//ie use settings-[site].json

		if (event != undefined)
		{
			if (event.site != undefined)
			{
				site = event.site;
				
			}
		}
		
		entityos.init(main, site);

		function main(err, data)
		{
			/*
				app initialises with entityos.invoke('app-init') after controllers added.
			*/

			entityos.add(
			{
				name: 'app-init',
				code: function ()
				{
					entityos._util.message('Using entityos module version ' + entityos.VERSION);
					entityos._util.message(entityos.data.session);

					var eventData = entityos.get(
					{
						scope: 'app',
						context: 'event'
					});

					var request =
					{ 
						body: {},
						queryString: {},
						headers: {}
					}

					if (eventData != undefined)
					{
						request.queryString = eventData.queryStringParameters;
						request.headers = eventData.headers;

						if (_.isString(eventData.body))
						{
							request.body = JSON.parse(eventData.body)
						}
						else
						{
							request.body = eventData.body;
						}	
					}

					entityos.set(
					{
						scope: 'app',
						context: 'request',
						value: request
					});

					console.log(request);
					
					if (eventData.path == '/.well-known/microsoft-identity-association.json')
					{
						entityos.invoke('util-end',
						{
							"associatedApplications": [
								{
								"applicationId": "..."
								}
							]
						},
						200)
					}
					else
					{
						entityos.invoke('app-space');
					}
				}
			});

			//SWITCH INTO SPACES

			entityos.add(
			{
				name: 'app-space',
				code: function (param)
				{
					var request = entityos.get(
					{
						scope: 'app',
						context: 'request'
					});

					if (request.body == null) 
					{
						request.body = {}
					}
					
					if (request.queryString == null) 
					{
						request.queryString = {}
					}

					request.state = request.queryString.state;
					if (request.state == undefined)
					{
						request.state = request.body.state;
					}

					if (request.state == undefined)
					{
						request.spaceGUID = request.body.s;
						request.spaceHash = request.body.h;
						request.connectionGUID = request.body.c;

						if (request.spaceGUID == undefined)
						{
							request.spaceGUID = request.queryString.s;
							request.spaceHash = request.queryString.h;  // requestSpaceGUID + requestSpaceETag > hash:sha256>base64
							request.connectionGUID = request.queryString.c;
						}

						request.state = request.spaceGUID + '|' + request.spaceHash + '|' + request.connectionGUID;
					}
					else
					{
						request._state = decodeURIComponent(request.state).split('|');
						request.spaceGUID = request._state[0];
						request.spaceHash = request._state[1];
						request.connectionGUID = request._state[2];
					}

					console.log('REQUEST:');
					console.log(request);

					entityos.set(
					{
						scope: 'app',
						context: 'request',
						value: request
					});

					entityos.cloud.search(
					{
						object: 'core_space',
						fields: ['etag'],
						filters:
						[
							{
								field: 'guid',
								comparison: 'EQUAL_TO',
								value: request.spaceGUID
							}
						],
						sorts:
						[
							{
								field: 'guid',
								direction: 'desc'
							}
						],
						callback: 'app-space-process'
					});
				}
			});

			//check hash is good
			entityos.add(
			{
				name: 'app-space-process',
				code: function (param, response)
				{
					console.log(response)

					if (response.status == 'ER')
					{
						entityos.invoke('util-end', {error: 'Error processing space authentication.'}, '401');
					}
					else
					{
						var request = entityos.get(
						{
							scope: 'app',
							context: 'request'
						});

						if (response.data.rows.length == 0)
						{
							entityos.invoke('util-end', {error: 'Bad s [' + request.spaceGUID + ']'}, '401');
						}
						else
						{
							var request = entityos.get(
							{
								scope: 'app',
								context: 'request'
							});

							request.space = _.first(response.data.rows);

							entityos.set(
							{
								scope: 'app',
								context: 'space',
								value: request.space
							});

							var _spaceHash = entityos.invoke('util-protect-hash', {text: request.spaceGUID + '-' + request.space.etag });

							console.log()

							if (_spaceHash != request.spaceHash)
							{
								entityos.invoke('util-end', {error: 'Bad h [' + request.spaceHash + ']'}, '401');
							}
							else
							{
								console.log('All good to switch into space using: ' + request.spaceGUID)
								entityos.invoke('app-space-switch')
							}
						}
					}
				}
			});

			entityos.add(
			{
				name: 'app-space-switch',
				code: function ()
				{
					var space = entityos.get(
					{
						scope: 'app',
						context: 'space'
					});

					entityos.cloud.invoke(
					{
						method: 'core_space_manage',
						data:
						{
							switch: '1',
							id: space.id
						},
						callback: 'app-space-switch-process'
					})
				}
			});

			entityos.add(
			{
				name: 'app-space-switch-process',
				code: function (param, response)
				{
					var request = entityos.get(
					{
						scope: 'app',
						context: 'request'
					});

					if (response.status == 'OK')
					{
						console.log('Switched into space using: ' + request.spaceGUID)
						entityos.invoke('app-auth');
					}
				}
			});

			entityos.add(
			{
				name: 'app-auth',
				code: function (param)
				{
					// Use the a key to check core_protect_key

					var request = entityos.get(
					{
						scope: 'app',
						context: 'request'
					});

					// request.connectionGUID (sent as request parameter "c")

					entityos.cloud.search(
					{
						object: 'core_protect_key',
						fields: ['guid'],
						filters:
						[
							{
								field: 'guid',
								comparison: 'EQUAL_TO',
								value: request.connectionGUID
							}
						],
						callback: 'app-auth-process'
					});
				}
			});

			entityos.add(
			{
				name: 'app-auth-process',
				code: function (param, response)
				{
					console.log(response)

					entityos.set(
					{
						scope: 'app',
						context: 'access',
						value: response
					});

					if (response.status == 'ER')
					{
						entityos.invoke('util-end', {error: 'Error processing access authentication.'}, '401');
					}
					else
					{
						var request = entityos.get(
						{
							scope: 'app',
							context: 'request'
						});

						if (response.data.rows.length == 0)
						{
							entityos.invoke('util-end', {error: 'Bad a [' + request.accessGUID + ']'}, '401');
						}
						else
						{
							request.connection = _.first(response.data.rows);

							entityos.set(
							{
								scope: 'app',
								context: 'request',
								value: request
							});

							entityos.invoke('app-start')
						}
					}
				}
			});

			entityos.add(
			{
				name: 'util-uuid',
				code: function (param)
				{
					var pattern = entityos._util.param.get(param, 'pattern', {"default": 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'}).value;
					var scope = entityos._util.param.get(param, 'scope').value;
					var context = entityos._util.param.get(param, 'context').value;

					var uuid = pattern.replace(/[xy]/g, function(c) {
						    var r = Math.random() * 16 | 0, v = c == 'x' ? r : (r & 0x3 | 0x8);
						    return v.toString(16);
						  });

					entityos.set(
					{
						scope: scope,
						context: context,
						value: uuid
					})
				}
			});

			entityos.add(
			{
				name: 'app-log',
				code: function ()
				{
					var eventData = entityos.get(
					{
						scope: 'app',
						context: 'event'
					});

					entityos.cloud.invoke(
					{
						object: 'core_debug_log',
						fields:
						{
							data: JSON.stringify(eventData),
							notes: 'app Log (Event)'
						}
					});

					var requestData = entityos.get(
					{
						scope: 'app',
						context: 'request'
					});

					entityos.cloud.invoke(
					{
						object: 'core_debug_log',
						fields:
						{
							data: JSON.stringify(requestData),
							notes: 'app Log (Request)'
						}
					});

					var contextData = entityos.get(
					{
						scope: 'app',
						context: 'context'
					});

					entityos.cloud.invoke(
					{
						object: 'core_debug_log',
						fields:
						{
							data: JSON.stringify(contextData),
							notes: 'appLog (Context)'
						},
						callback: 'app-log-saved'
					});
				}
			});

			entityos.add(
			{
				name: 'app-log-saved',
				code: function (param, response)
				{
					entityos._util.message('Log data saved to entityos.cloud');
					entityos._util.message(param);
					entityos._util.message(response);
				
					entityos.invoke('app-respond')
				}
			});

			entityos.add(
			{
				name: 'util-end',
				code: function (data, statusCode, headers)
				{
					if (statusCode == undefined) { statusCode: '200' }

					entityos.set(
					{
						scope: 'app',
						context: 'response',
						value: {data: data, statusCode: statusCode, headers: headers}
					});

					entityos.invoke('app-respond')
				}
			});

			entityos.add(
			{
				name: 'app-respond',
				code: function (response)
				{
					if (response == undefined)
					{
						response = entityos.get(
						{
							scope: 'app',
							context: 'response'
						});
					}

					var statusCode = response.httpStatus;
					if (statusCode == undefined) {statusCode = '200'}

					var body = response.data;

					if (body == undefined) {body = {}}

					var headers = response.headers;
					if (headers == undefined) {headers = {}}
					
					if (_.isPlainObject(body))
					{
						headers['content-type'] = 'application/json';
						body = JSON.stringify(body)
					}
					else if (_.startsWith(body, '<'))
					{
						headers['content-type'] = 'text/html'
					}

					let httpResponse =
					{
						statusCode: statusCode,
						headers: headers,
						body: body
					};
					
					resolve(httpResponse)
				}
			});

			entityos.add(
			{
				name: 'app-start',
				code: function ()
				{
					var request = entityos.get(
					{
						scope: 'app',
						context: 'request'
					});

					var mode;
					var method;

					var data = request.body;

					if (data != undefined)
					{
						var mode = data.mode;
						var method = data.method;
					}

					if (_.isString(mode))
					{
						mode = {type: mode, status: 'OK'}
					}

					if (mode == undefined)
					{
						mode = {type: 'live', status: 'OK'}
					}

					if (mode.status == undefined)
					{
						mode.status = 'OK';
					}

					mode.status = mode.status.toUpperCase();

					if (mode.type == 'reflect')
					{
						var response = {}

						if (mode.data != undefined)
						{
							response.data = mode.data;
						}
						
						entityos.invoke('util-uuid',
						{
							scope: 'guid',
							context: 'log'
						});

						response.data = _.assign(response.data,
						{
							status: mode.status,
							method: method,
							reflected: data,
							guids: entityos.get(
							{
								scope: 'guid'
							})
						});

						entityos.set(
						{
							scope: 'app',
							context: 'response',
							value: response
						});

						entityos.invoke('app-respond');
					}
					else
					{
						entityos.invoke('app-process');
					}
				}
			});

			entityos.add(
			{
				name: 'app-process',
				code: function ()
				{
					var request = entityos.get(
					{
						scope: 'app',
						context: 'request'
					});

					var data = request.body;

					var method;

					if (data != undefined)
					{
						method = data.method;
					}

					if (method == undefined)
					{
						if (_.has(request.queryString, 'code'))
						{
							//if request has code then set method = 'set-consent' - ie from redirectURI
							method = 'set-consent';
						}
						else
						{
							method = 'get-consent';
						}
					}
		
					if (method == 'get-consent' || method == 'set-consent')
					{
						entityos.invoke('app-process-' + method)
					}
					else
					{
						entityos.set(
						{
							scope: 'app',
							context: 'response',
							value:
							{
								status: 'ER',
								data: {error: {code: '2', description: 'Not a valid method [' + method + ']'}}
							}
						});

						entityos.invoke('app-respond');
					}
				}
			});

//--- GET_CONSENT

			entityos.add(
			{
				name: 'app-process-get-consent',
				code: function ()
				{
					var request = entityos.get(
					{
						scope: 'app',
						context: 'request'
					});

					var settings = entityos.get({scope: '_settings'});

					console.log('!!! app-process-get-consent');
					
					if (settings.msal == undefined)
					{
						console.log('!!! NO MSAL SETTINGS')
					}
					else
					{
						var msalConfig =
						{
							auth: {
								clientId: settings.msal.clientID , // 'Application (client) ID' of app registration in Azure portal - this value is a GUID
								clientSecret: settings.msal.clientSecret,
								authority: 'https://login.microsoftonline.com/common' // Full directory URL, in the form of https://login.microsoftonline.com/<tenant>
							}
						}

						console.log(msalConfig)

						const msalInstance = new msal.ConfidentialClientApplication(msalConfig);						
						const cryptoProvider = new msal.CryptoProvider();

						cryptoProvider.generatePkceCodes()
						.then(function (data)
						{
							request.PkceCodes = data;

							entityos.set(
							{
								scope: 'app',
								context: 'request',
								value: request
							});

							console.log(data);

							var authCodeUrlRequest =
							{
								redirectUri: settings.msal.redirectURL,
								codeChallenge: data.challenge,
								codeChallengeMethod: 'S256',
								state: request.state,
								scopes:
								[
									'offline_access',
									'email',
									'openid',
									'profile',
									'User.Read',
									'Mail.Send',
									'Mail.ReadWrite',
									'SMTP.Send',
									'https://outlook.office.com/SMTP.Send',
									'https://outlook.office.com/IMAP.AccessAsUser.All'
								]
							}

							msalInstance.getAuthCodeUrl(authCodeUrlRequest)
							.then(
								function (data)
								{
									var request = entityos.get(
									{
										scope: 'app',
										context: 'request'
									});

									request.consentURL = data;

									entityos.set(
									{
										scope: 'app',
										context: 'request',
										value: request
									});

									console.log(request.consentURL);

									entityos.invoke('app-process-get-consent-response', {consentURL: request.consentURL});
								}
							)
							.catch(
								function (data)
								{
									entityos.invoke('util-end', {error: data.errorMessage}, '500');
								}
							);
						})
						.catch(
							function (data)
							{
								entityos.invoke('util-end', {error: data.errorMessage}, '500');
							}
						);
					}
				}
			});

			entityos.add(
			{
				name: 'app-process-get-consent-response',
				code: function (param)
				{
					var request = entityos.get(
					{
						scope: 'app',
						context: 'request'
					});

					if (request.consentURL == undefined)
					{
						entityos.invoke('util-end', {error: 'Can not get consent URL.'}, '500');
					}
					else
					{
						console.log(request)

						entityos.cloud.save(
						{
							object: 'core_protect_key',
							data:
							{
								id: request.connection.id,
								key: request.PkceCodes.verifier
							},
							callback: 'app-process-get-consent-response-resolve'
						});
					}
				}
			});

			entityos.add(
			{
				name: 'app-process-get-consent-response-resolve',
				code: function (param, response)
				{
					var request = entityos.get(
					{
						scope: 'app',
						context: 'request'
					});

					let httpResponse =
					{
						statusCode: 302,
						headers:
						{
							"Access-Control-Allow-Origin": "*",
							Location: request.consentURL
						}
					};

					resolve(httpResponse)
				}
			});

//--- SET_CONSENT

			entityos.add(
			{
				name: 'app-process-set-consent',
				code: function ()
				{
					var request = entityos.get(
					{
						scope: 'app',
						context: 'request'
					});

					request.authZCode = request.queryString.code;
					if (request.authZCode == undefined)
					{
						request.authZCode = request.body.code;
					}

					entityos.cloud.search(
					{
						object: 'core_protect_key',
						fields: ['key'],
						filters:
						[
							{
								field: 'guid',
								comparison: 'EQUAL_TO',
								value: request.connectionGUID
							}
						],
						callback: 'app-process-set-consent-reponse'
					});
				}
			});

			entityos.add(
			{
				name: 'app-process-set-consent-reponse',
				code: function (param, response)
				{
					var request = entityos.get(
					{
						scope: 'app',
						context: 'request'
					});

					request.connection = _.first(response.data.rows);
					request.codeVerifier = request.connection.key;
					
					console.log(request);

					entityos.set(
					{
						scope: 'app',
						context: 'request',
						value: request
					});

					entityos.invoke('app-process-set-consent-tokens')
				}
			});


			entityos.add(
			{
				name: 'app-process-set-consent-tokens',
				code: function ()
				{
					var request = entityos.get(
					{
						scope: 'app',
						context: 'request'
					});

					var settings = entityos.get({scope: '_settings'});

					//Use the state to search the space for the connection (core_protect_key.guid)

					var authCodeRequest =
					{
						code: request.authZCode,
						codeVerifier: request.codeVerifier,
						redirectUri: settings.msal.redirectURL
					}

					var msalConfig =
					{
						auth: {
							clientId: settings.msal.clientID, // 'Application (client) ID' of app registration in Azure portal - this value is a GUID
							clientSecret: settings.msal.clientSecret,
							authority: 'https://login.microsoftonline.com/common' // Full directory URL, in the form of https://login.microsoftonline.com/<tenant>
						}
					}

					const msalInstance = new msal.ConfidentialClientApplication(msalConfig);	//get config from request.
					console.log(msalInstance)

					msalInstance.acquireTokenByCode(authCodeRequest).then(function (tokenResponse)
					{
						request.accessToken = tokenResponse.accessToken;
						request.idToken = tokenResponse.idToken;
						request.account = tokenResponse.account;
						request.isAuthenticated = true;

						console.log(tokenResponse);

						var tokenCache = msalInstance.getTokenCache().serialize();

						const refreshTokenObject = (JSON.parse(tokenCache)).RefreshToken;
						request.refreshToken = refreshTokenObject[Object.keys(refreshTokenObject)[0]].secret;

						entityos.invoke('app-process-set-consent-tokens-response')
					})
					.catch(
						function (data)
						{
							entityos.invoke('util-end', {error: data.errorMessage}, '500');
						}
					);
				}
			});

			entityos.add(
			{
				name: 'app-process-set-consent-tokens-response',
				code: function (param)
				{
					var request = entityos.get(
					{
						scope: 'app',
						context: 'request'
					});

					if (request.accessToken == undefined)
					{
						entityos.invoke('util-end', {error: 'Can not set consent tokens.'}, '500');
					}
					else
					{
						entityos.invoke('app-process-set-consent-response-persist-refresh-token')
					}
				}
			});

			entityos.add(
			{
				name: 'app-process-set-consent-response-persist-refresh-token',
				code: function (param, response)
				{
					var request = entityos.get(
					{
						scope: 'app',
						context: 'request'
					});

					console.log(request.connection);

					if (response == undefined)
					{
						entityos.cloud.save(
						{
							object: 'core_protect_key',
							data:
							{
								id: request.connection.id,
								key: request.refreshToken
							},
							callback: 'app-process-set-consent-response-persist-refresh-token'
						});
					}
					else
					{
						entityos.invoke('util-end',
							'<div style="background-color: #f5f5f5; color: #333333; width: 350px; padding: 30px; text-align: center; font-size: 14px; margin-right: auto !important; margin-left: auto !important; font-family: Helvetica Neue,Helvetica,Arial,sans-serif; margin-top: 30px; border-radius: 6px;">' +
								'<p style="font-weight: 500; font-size: 1.6em; margin-bottom: 26px; margin-top: 8px;">Connection Established!</p>' +
								'<div style="color: #607d8b">You can now close this window.</div>' +
							'</div>',
							'200');
					}
				}
			});

			entityos.add(
			{
				name: 'util-protect-hash',
				code: function (param)
				{
					const { createHash } = require('crypto');

					if (param.hashMethod == undefined)
					{
						param.hashMethod = 'sha256'
					}

					if (param.output == undefined)
					{
						param.output = 'base64'
					}

					if (param.text == undefined && param.data != undefined)
					{
						param.text = JSON.stringify(param.data);
						if (param.escape)
						{
							param.text = _.escape(param.text);
						}
					}

					return createHash(param.hashMethod).update(param.text).digest(param.output);
				}
			});

	
			// !!!! APP STARTS HERE; Initialise the app; app-init invokes app-start if authentication OK
			entityos.invoke('app-init');
		}		
   	});

  	return promise
}