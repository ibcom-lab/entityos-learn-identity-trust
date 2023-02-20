var _ = require('lodash')
var moment = require('moment');
var entityos = require('entityos/entityos.js');
var XLSX = require('xlsx/xlsx.js');
var XLSXops = require('xlsx/xlsxops.js');
var numeral = require('numeral/numeral.js');
var request = require('request');

module.exports = 
{
	VERSION: '1.0.2',

	data: {},

	sheet:
	{
		data: {},

		init: function (param)
		{
			var filename = entityos._util.param.get(param, 'filename', {default: 'export.xlsx'}).value;
			var exportData = entityos._util.param.get(param, 'data').value;
			var templateAttachment = entityos._util.param.get(param, 'templateAttachment').value;
			var store = entityos._util.param.get(param, 'store', {default: true}).value;

			entityos._util.param.set(param, 'exportData', exportData);

			var url = entityos._util.param.get(param, 'url').value; 

			if (url == undefined)
			{
				if (templateAttachment != undefined)
				{
					var settings = entityos.get({scope: '_settings'});
					var session = entityos.data.session;

					url = 'https://' + settings.entityos.hostname + '/rpc/core/?method=CORE_ATTACHMENT_DOWNLOAD&id=' + templateAttachment +
							'&sid=' + session.sid + '&logonkey=' + session.logonkey;
				}
			}

			var exportFormats = entityos._util.param.get(param, 'formats').value; 

			if (url == undefined)
			{
				entityos._util.log.add(
				{
					message: 'entityos._util.export.sheet; no template URL'
				});
			}
			else
			{
				request(url, {encoding: null}, function(err, res, data)
				{
					if (err || res.statusCode !== 200)
					{
						console.log(err);
					}

					var workbook = XLSX.read(data, {type:'buffer', cellStyles: true, bookImages: true});

				  	var sheetData = {};

				  	if (workbook.Workbook != undefined)
				  	{
					  	sheetData.names = workbook.Workbook.Names;

                        //CHECK IF NEED TO INSERT ANY CELLS BASED ON RANGES AND THEN ADJUST NAMES IN THE WORK BOOK.

						_.each(exportFormats, function (format)
						{
							if (format.range != undefined)
							{
								_.each(sheetData.names,  function (name)
								{
									name.sheet = _.replaceAll(_.first(_.split(name.Ref, '!')), "'", '');
						 			name.cell = _.replaceAll(_.last(_.split(name.Ref, '!')), '\\$', '');
									name.row = numeral(name.cell).value();
									name.col = _.replace(name.cell, name.row, '');

									if (format.range.header != undefined)
									{
										if (format.range.header.name != undefined)
										{
											if (format.range.header.name.toLowerCase() == name.Name.toLowerCase())
											{
												format.range.header.cell = name.cell;
											}
										}

										if (format.range.header.firstRow)
										{
											format.range.header.cell =
												(format.range.header.firstRowColumn!=undefined?format.range.header.firstRowColumn:'A') + '1';
										}
									}

									if (format.range.footer != undefined)
									{
										if (format.range.footer.name != undefined)
										{
											if (format.range.footer.name.toLowerCase() == name.Name.toLowerCase())
											{
												format.range.footer.cell = name.cell;
											}
										}

										if (format.range.footer.lastRow)
										{
											format.range.footer.cell = (format.range.footer.lastRowColumn!=undefined?format.range.footer.lastRowColumn:'A') +
													(parseInt(sheetData.names[format.sheet].maximumRow) + 1);
										}
									}
								});

								var headerRow = numeral(format.range.header.cell).value(); //45
								var footerRow = numeral(format.range.footer.cell).value(); //53
				   
								format.fieldsStartRow = headerRow + 1; //46
								format.fieldsEndRow = footerRow - 1; //52
				   		   
								var rows = _.range(format.fieldsStartRow, format.fieldsEndRow + 1);
								
								var data = _.find(exportData, function(_exportData)
								{
									return (_exportData.object == format.storage.object 
												&& _exportData.field == format.storage.field)
								});

								worksheet = workbook.Sheets[format.sheet];

								//Split into seperate validations
								_.each(worksheet['!validations'], function (validation)
								{
									if (!_.isPlainObject(validation.ref))
									{
										var _ref = _.split(validation.ref, ' ');
										if (_ref.length > 1)
										{
											var _validations = [];

											_.each(_ref, function (ref, r)
											{
												if (r==0)
												{
													validation.ref = ref;
												}
												else
												{
													var _validation = _.cloneDeep(validation);
													_validation.ref = ref;
													_validations.push(_validation);
												}
											});

											worksheet['!validations'] = _.concat(worksheet['!validations'], _validations);
										}
									}
								});
							   
								if (data != undefined)
								{
                                    console.log('ADD ROWS');
                                    console.log(data);

									format.rowsToAdd = (data.value.length - rows.length + 1);
									if (format.rowsToAdd < 0) {format.rowsToAdd = 0}
									
                                    console.log(format);

                                    console.log(data.value.length);
                                    console.log(rows.length);
                                    console.log(format.rowsToAdd);

									if (format.rowsToAdd > 0)
									{
										worksheet = workbook.Sheets[format.sheet];

										XLSXops.insert_rows(worksheet, format.fieldsEndRow, format.rowsToAdd);

										format.rowsImpactedAfter = format.fieldsEndRow;

										_.each(sheetData.names,  function (name)
										{
											if ((name.row > format.rowsImpactedAfter) && (name.sheet == format.sheet))
											{
												name.row = name.row + format.rowsToAdd;
												name.cell = name.col + name.row;
												name.Ref = '\'' + name.sheet + '\'!$' + name.col + '$' + name.row;
											}
										});

										var newRows = _.range(format.fieldsEndRow + 1, (format.fieldsEndRow + format.rowsToAdd + 1));
										
                                        var minCol = 99999;
                                        var maxCol = 0;

										_.each(format.range.fields, function (field)
										{
											field._cellRC = XLSX.utils.decode_cell(field.column + format.fieldsEndRow);

                                            if (field._cellRC.c < minCol) {minCol = field._cellRC.c}
                                            if (field._cellRC.c > maxCol) {maxCol = field._cellRC.c}

											field.merge = _.find(worksheet['!merges'], function (merge)
											{
												return (merge.s.c == field._cellRC.c) && (merge.s.r == field._cellRC.r);
											});

                                            if (field.merge != undefined)
                                            {
                                                if (field.merge.e.c > maxCol) {maxCol = field.merge.e.c}
                                            }
										});

										_.each(newRows, function (newRow)
										{
                                            var fieldColumns = _.range(minCol, (maxCol + 1));

											_.each(fieldColumns, function (column)
											{
                                                var newCell = XLSX.utils.encode_cell({r: (newRow - 1), c: column});
                                                var cloneCell = XLSX.utils.encode_cell({r: (format.fieldsEndRow - 1), c: column});

                                                worksheet[newCell] = _.cloneDeep(worksheet[cloneCell]);
												//worksheet[column + newRow] = _.cloneDeep(worksheet[column + format.fieldsEndRow]);
											});

											_.each(format.range.fields, function (field)
											{
												if (field.merge != undefined)
												{
													var newMerge = _.cloneDeep(field.merge);
													newMerge.s.r = (newRow - 1);
													newMerge.e.r = (newRow - 1);
													worksheet['!merges'].push(newMerge);
												}
											});

                                            worksheet['!rows'][(newRow - 1)] = worksheet['!rows'][(format.fieldsEndRow - 1)];
										});

                                        _.each(worksheet['!validations'], function (validation)
                                        {
                                            if (!_.isPlainObject(validation.ref))
                                            {
                                                validation.ref = XLSX.utils.decode_range(validation.ref);
                                            }
                                            
                                            validation.ref.e.r = validation.ref.e.r + format.rowsToAdd;
                                        });
									}
							   }
							}
						});

                        //RESOLVE NAMES TO CELLS

					  	_.each(sheetData.names, function (name)
					  	{
					  		name.sheet = _.replaceAll(_.first(_.split(name.Ref, '!')), "'", '');
							name.cell = _.replaceAll(_.last(_.split(name.Ref, '!')), '\\$', '');

					  		_.each(exportFormats, function (format)
							{
								if (format.name != undefined)
								{
									if (format.name.toLowerCase() == name.Name.toLowerCase() 
											&& format.sheet == name.sheet)
									{
			   						format.cell = name.cell;
									}
								}

                                if (format.range != undefined)
								{
									if (format.range.header != undefined)
									{
										if (format.range.header.name != undefined)
										{
											if (format.range.header.name.toLowerCase() == name.Name.toLowerCase())
											{
												format.range.header.cell = name.cell;
											}
										}

										if (format.range.header.firstRow)
										{
											format.range.header.cell =
												(format.range.header.firstRowColumn!=undefined?format.range.header.firstRowColumn:'A') + '1';
										}
									}

									if (format.range.footer != undefined)
									{
										if (format.range.footer.name != undefined)
										{
											if (format.range.footer.name.toLowerCase() == name.Name.toLowerCase())
											{
												format.range.footer.cell = name.cell;
											}
										}

										/*if (format.range.footer.lastRow)
										{
											format.range.footer.cell = (format.range.footer.lastRowColumn!=undefined?format.range.footer.lastRowColumn:'A') +
													(numeral(sheetData.sheets[format.sheet].maximumRow).value() + 1);
										}*/
									}
								}
							});
					  	});
					}

				  	// GO THROUGH FORMATS AND WRITE VALUES TO WORKSHEETS

				  	var worksheet;
				  	var cell;
				  	var value;

				  	_.each(exportFormats, function (format)
				  	{
				  		if (format.sheet != undefined)
				  		{
                            worksheet = workbook.Sheets[format.sheet];

					  		value = format.value;

                            if (format.range != undefined)
                            {
                                module.exports.sheet.range(format, workbook, worksheet, exportData);
                            }	
                            else
                            { 
                                if (format.storage != undefined)
                                {
                                    var storageData = _.find(exportData, function (data)
                                    {
                                        return data.field == format.storage.field;
                                    });

                                    if (storageData != undefined)
                                    {
                                        if (storageData.value != undefined)
                                        {
                                            value = _.unescape(_.unescape(storageData.value))
                                        }
                                    }
                                }

                                if (worksheet != undefined)
                                {
                                    cell = worksheet[format.cell];

                                    if (cell == undefined)
                                    {
                                        cell = {};
                                    }

                                    cell.t = 's';

                                    if (format.type != undefined)
                                    {
                                        cell.t = format.type;
                                    }
                                
                                    cell.v = (value!=undefined?value:'');
                                }
                            }
						}
					});

				  	sheetData.workbook = workbook;

				  	//https://github.com/sheetjs/sheetjs#writing-options
			
					if (true)
					{
						sheetData.base64 = XLSX.write(workbook, {type: 'base64', cellStyles: true, bookImages: true});
						sheetData.array = XLSX.write(workbook, {type: 'array', cellStyles: true, bookImages: true});
						sheetData.buffer = XLSX.write(workbook, {type: 'buffer', cellStyles: true, bookImages: true});

						module.exports.sheet.store.save(param,
						{
							base64: sheetData.base64,
							binary: sheetData.binary,
							array: sheetData.array,
							buffer: sheetData.buffer
						});
					}	
					else
					{
						//For debugging;
						XLSX.writeFile(workbook, 'checklist-debug.xlsx', {cellStyles: true, bookImages: true});
					}				
				});
			}
		},

        range: function (format, workbook, worksheet, exportData)
 		{
 			//Use range header to get cells to work through
 			//Assume cells have been resolved

 			var headerCell = format.range.header.cell; // A45
 			var headerRow = numeral(format.range.header.cell).value(); //45

 			var footerCell = format.range.footer.cell; // A53
 			var footerRow = numeral(format.range.footer.cell).value(); //53

 			var fieldsStartRow = headerRow + 1; //46
 			var fieldsEndRow = footerRow - 1; //52

 			var fields = format.range.fields;

 			var importData = []

 			var rows = _.range(fieldsStartRow, fieldsEndRow + 1);
 			
 			if (format.name == undefined)
 			{
 				format.name = _.camelCase(format.caption).toLowerCase();
 			}

 			var data = _.find(exportData, function(_exportData)
			{
				return (_exportData.object == format.storage.object 
							&& _exportData.field == format.storage.field)
			})
			
			if (data != undefined)
			{
				_.each(rows, function (row, r)
				{
					rowFields = _.cloneDeep(fields);
					rowData = data.value[r];

                    if (rowData != undefined)
                    {
                        _.each(rowFields, function (field)
                        {
                            field.suffix = (r + 1);
                            field.row = row;
                            field.cell = field.column + field.row;  

                            field._cell = worksheet[field.cell];
                            field._processing = {name: format.name + '-' + field.name + '-' + field.suffix, validate: {}, notes: {}}

                            if (field._cell != undefined)
                            {
                                var value = rowData[field.name]

                                if (value != undefined)
                                {
                                    field._cell.t = 's';

                                    if (format.type != undefined)
                                    {
                                        field._cell.t = format.type;
                                    }

                                    if (_.has(field, 'format.values'))
                                    {
                                        if (field.format.values[value] != undefined)
                                        {
                                            value = field.format.values[value]
                                        }
                                    }
                                
                                    field._cell.v = (value!=undefined?value:'');
                                }

                                if (_.has(field, 'defaults.hasValue.style'))
                                {
                                     _.assign(field._cell.s, field.defaults.hasValue.style)   
                                }
                            }
                        });
                    }
				});
			}
 		},

		store:
		{
			save: function (param, fileData)
			{
				var filename = entityos._util.param.get(param, 'filename', {default: 'export.xlsx'}).value;
				var object = entityos._util.param.get(param, 'object', {default: 107}).value;
				var objectContext = entityos._util.param.get(param, 'objectContext').value;
				var base64 = entityos._util.param.get(param, 'base64', {default: false}).value;
				var type = entityos._util.param.get(param, 'type').value;

				if (base64)
				{
					entityos.cloud.invoke(
					{
						method: 'core_attachment_from_base64',
						data:
						{
							base64: fileData.base64,
							filename: filename,
							object: object,
							objectcontext: objectContext
						},
						callback: module.exports.sheet.store.process,
						callbackParam: param
					});
				}
				else
				{
					var settings = entityos.get({scope: '_settings'});
					var session = entityos.data.session;

					var blob = Buffer.from(fileData.buffer)

					var FormData = require('form-data');
					var form = new FormData();
		
					form.append('file0', blob,
					{
						contentType: 'application/octet-stream',
						filename: filename
					});
					form.append('filename0', filename);
					form.append('object', object);
					form.append('objectcontext', objectContext);
					form.append('method', 'ATTACH_FILE');
					form.append('sid', session.sid);
					form.append('logonkey', session.logonkey);

					if (!_.isUndefined(type))
					{
						form.append('type0', type);
					}

					var url = 'https://' + settings.entityos.hostname + '/rpc/attach/'

					form.submit(url, function(err, res)
					{
						res.resume();

						res.setEncoding('utf8');
						res.on('data', function (chunk)
						{
							var data = JSON.parse(chunk);
						   module.exports.sheet.store.process(param, data)
						});
					});
				}
			},

			process: function (param, response)
			{
				var controller = entityos._util.param.get(param, 'controller').value;

				if (response.status == 'OK')
				{
					var attachment;

					if (_.has(response, 'data.rows'))
					{
						attachment = _.first(response.data.rows);
					}
					else
					{
						attachment = response;
					}

					var data =
					{
						attachment:
						{
							id: attachment.attachment,
							link: attachment.attachmentlink,
							href: '/download/' + attachment.attachmentlink
						}
					}
				}

				param = entityos._util.param.set(param, 'data', data);

				module.exports.sheet.store.complete(param)
				
			},
		
			complete: function (param)
			{
                //Should be onComplete
				entityos.invoke('app-process-add-scheduled-audit-process-checklist-send', param)
			}
		}
	}
	
}